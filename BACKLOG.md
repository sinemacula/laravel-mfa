# Backlog

Running log of issues, gaps, and architectural questions resolved while building `sinemacula/laravel-mfa`.

---

## Status — ✅ Phases 1–5 and Phase 9 (tests) complete

- **100% line / method / class coverage** on `src/` (498/498 lines, 134/134 methods, 26/26 classes)
- **298 tests passing** across Unit / Feature / Integration / Performance suites
- **Mutation testing gate green** — 92% Covered MSI on scoped paths (gate: 90%)
- **PHPBench benchmarks** covering every hot-path (TOTP, OTP, backup codes, FactorSummary)
- **`composer check` clean** on `src/` and `benchmarks/` (only pre-existing markdown lint + informational radarlint code-smell warnings remain)

Remaining optional work is tracked in the Phase 6 / 7 sections below — enrolment helpers, code-alphabet config, step-up middleware, replay protection, and rate-limit docs.

---

## Summary

The current `src/` is a partial scaffold extracted from the `laravel-iam` monorepo. The public surface (manager,
middleware, facade, exceptions, contracts) is broadly the right shape, but the package has significant gaps against
its own PRD (`docs/prd/02-laravel-mfa.md`) and several architectural decisions need to be resolved before wiring the
package into either of its intended adoption modes:

1. **Standalone mode** — works with any Laravel auth stack (SessionGuard, Sanctum, Passport, custom guard).
2. **Paired mode** — complements `sinemacula/laravel-authentication`, whose `Device` contract already exposes
   `getLastMfaVerification()` and whose migration already ships a `last_mfa_verified_at` column. The verification
   lifecycle therefore needs to be storage-agnostic, not hard-wired to session state.
3. **IAM parent mode** — wrapped by `sinemacula/laravel-iam` along with the other sibling packages, with the parent
   package providing the glue (e.g. binding the device-backed verification store, wiring organisation enforcement,
   registering cross-package event listeners).

This backlog groups findings by theme. Line references are to files as they stand today.

---

## Current `src/` inventory

| File                                          | Role                                                          | State                                                           |
|-----------------------------------------------|---------------------------------------------------------------|-----------------------------------------------------------------|
| `MfaManager.php`                              | Manager pattern dispatcher + state inspection                 | Present; session-only storage; organisation enforcement stubbed |
| `MfaServiceProvider.php`                      | Service provider; registers `mfa` singleton, publishes config | Present; does not register middleware aliases or facade alias   |
| `Facades/Mfa.php`                             | Static facade                                                 | Present                                                         |
| `Contracts/EnforcesMfa.php`                   | Organisation-level enforcement contract                       | Present; orphaned — no resolver wires it into the manager       |
| `Contracts/FactorDriver.php`                  | Factor driver contract                                        | Present; `verify(string, mixed)` signature is too loose         |
| `Contracts/MultiFactorAuthenticatable.php`    | Identity capability contract                                  | Present; extends `Authenticatable` (standalone-safe)            |
| `Drivers/TotpDriver.php`                      | TOTP verification via `pragmarx/google2fa`                    | Present; runtime dependency check in place                      |
| `Drivers/EmailDriver.php`                     | Email OTP verification                                        | Verify only — no code generation, no delivery hook              |
| `Drivers/SmsDriver.php`                       | SMS OTP verification                                          | Verify only — no code generation, no gateway contract           |
| `Middleware/RequireMfa.php`                   | Route enforcement                                             | Present; binary (no step-up variant)                            |
| `Middleware/SkipMfa.php`                      | Route exemption                                               | Present                                                         |
| `Exceptions/MfaRequiredException.php`         | Thrown when MFA needed                                        | Present; extends `HttpException` (401) with factor payload      |
| `Exceptions/MfaExpiredException.php`          | Thrown when previous verification expired                     | Present; extends `HttpException` (401) with factor payload      |
| `Exceptions/MissingDriverDependencyException` | Surface for missing suggested deps                            | Present; extends `RuntimeException`                             |

Missing entirely:

- No `Models/` directory — no Factor model, no Attempt model (PRD P0 requires both).
- No `database/migrations/` content (PRD P0 requires publishable migrations).
- No `Events/` directory — no lifecycle events dispatched (inconsistent with `laravel-authentication`).
- No `Contracts\SmsGateway` (PRD P0 requirement).
- No `Drivers\BackupCodeDriver` (PRD P0 requirement).
- No storage abstraction for verification state (see architectural notes below).

---

## Gap analysis vs PRD P0 requirements

| PRD P0 requirement                            | Status     | Notes                                                                                                       |
|-----------------------------------------------|------------|-------------------------------------------------------------------------------------------------------------|
| Standalone integration with any auth stack    | ⚠️ Partial | Contracts are standalone-safe. `hasExpired()` forcing `session.store` excludes JWT/stateless stacks.        |
| TOTP factor driver                            | ✅ Mostly   | Works; no QR-code provisioning helper yet.                                                                  |
| Email code factor driver                      | ❌ Partial  | Verifies a stored code. No code generation. No mail dispatch. No attempt increment path.                    |
| SMS code factor driver with pluggable gateway | ❌ Missing  | No gateway contract, no null default that fails loud, no fake for tests, no dispatch path.                  |
| Backup code factor driver                     | ❌ Missing  | Not implemented.                                                                                            |
| Custom driver extension API                   | ✅          | Inherited from Laravel's `Manager::extend()`.                                                               |
| Route enforcement middleware                  | ✅          | `RequireMfa` throws structured exceptions.                                                                  |
| Route skip mechanism                          | ✅          | `SkipMfa` sets the `skip_mfa` request attribute.                                                            |
| Structured MFA exceptions                     | ✅          | Both exceptions extend `HttpException` and carry factor arrays.                                             |
| MFA state inspection API                      | ⚠️ Partial | `shouldUse` / `isSetup` / `hasExpired` exposed; no way to *complete* a verification (no "verified" setter). |
| Polymorphic identity support                  | ❌          | Contract exposes `authFactors(): Builder` but no Factor model or polymorphic migration to support it.       |
| Constant-time code verification               | ✅          | `hash_equals` in email/SMS drivers; Google2FA handles TOTP internally.                                      |
| Publishable, customisable migrations          | ❌          | Directory is empty.                                                                                         |
| Customisable factor / attempt Eloquent models | ❌          | No models ship, so nothing to rebind.                                                                       |
| Per-factor and global expiry                  | ⚠️ Partial | Config shape supports it; drivers accept per-driver expiry; global expiry only consulted in `hasExpired()`. |
| Per-factor max attempt limits                 | ⚠️ Partial | Drivers consult `attempts` but nothing increments it — the limit is a read-only threshold today.            |

---

## Architectural concerns

### A1. Verification state storage is hard-coded to the session

`MfaManager::hasExpired()` resolves `session.store` and reads `mfa_verified_at`. Nothing in `src/` writes that value;
the *consumer* is expected to. Two concrete problems:

- **JWT / stateless stacks break.** The paired package `laravel-authentication` is sessionless. Its `Device` contract
  already exposes `getLastMfaVerification(): ?CarbonInterface` (see
  `laravel-authentication/src/Contracts/Device.php:43`) and its migration ships `last_mfa_verified_at` (see
  `laravel-authentication/database/migrations/2026_04_06_000000_create_devices_table.php:59`). Session-only storage
  means paired-mode apps have two truths for the same fact.
- **No write path.** Middleware reads the timestamp; no manager method writes it. Consumers have to know the magic
  session key, set it manually, and trust the package's read path. That contract is currently implicit and fragile.

**Proposed direction:** introduce a `Contracts\MfaVerificationStore` interface with at least `markVerified(identity)`,
`lastVerifiedAt(identity): ?int`, and `forget(identity)`. Ship two implementations:

- `Stores\SessionMfaVerificationStore` — default, used in standalone mode.
- `Stores\DeviceMfaVerificationStore` — opt-in, reads/writes `last_mfa_verified_at` via the authentication package's
  `Device` contract. Bound by `laravel-iam` glue, **not** by this package directly (zero hard dependency).

Manager delegates to the bound store instead of reaching into the session.

### A2. `EnforcesMfa` is the wrong shape — replace with a generic `MfaPolicy` contract

**Resolved (see decisions below).** `EnforcesMfa` anchors on "the thing being enforced" and forces the manager to
know how to find it (an organisation, a tenant, a role). The right shape is a single bindable policy:

```php
interface MfaPolicy
{
    public function shouldEnforce(Authenticatable $identity): bool;
}
```

`MfaManager::shouldUse()` becomes `identity->shouldUseMultiFactor() || $policy->shouldEnforce($identity)`. Default
binding is `NullMfaPolicy` (returns `false`) so standalone apps never notice. Consumers wanting org-level, role-level,
or feature-flag-level enforcement bind their own implementation. `laravel-iam` can ship an opinionated
`OrganisationMfaPolicy` at its layer, where "organisation" is in scope. The MFA package never learns the word.

### A3. No unified "verify" entry point on the manager

Today a consumer has to:

1. Resolve a driver (`Mfa::driver('totp')`).
2. Call `verify($code, $factor)`.
3. On success, set the session key manually (and increment attempts themselves on failure).
4. On failure, know to increment the factor's `attempts` column themselves.

Every consumer will implement the same orchestration. The manager should expose a single `Mfa::verify($driver, $code,
$factor)` (or similar) that runs the driver, increments attempts on failure via the attempt model, marks verified via
the storage abstraction on success, and dispatches events. This is where the package earns its keep.

### A4. `FactorDriver::verify(string, mixed)` is too loose

`mixed $factor` pushes type-checking into each driver's private `extract*()` helpers. This is also why `EmailDriver`
and `SmsDriver` duplicate ~40 lines of extraction logic verbatim.

**Proposed direction:** introduce a `Contracts\Factor` interface (or a concrete Eloquent `Factor` model that drivers
can type-hint directly). Drivers then read typed properties (`$factor->getSecret()`, `$factor->getCode()`,
`$factor->getExpiresAt()`) rather than sniffing `stdClass` vs. array.

### A5. No SMS gateway contract

PRD P0: "The package defines a single SMS gateway contract; the default binding is a null implementation that throws
a clear, actionable error explaining how to bind a real gateway; an integration test demonstrates verification
end-to-end using a fake gateway implementation."

Currently: `SmsDriver` doesn't know how to send anything. Need `Contracts\SmsGateway` with a minimal `send(string
$to, string $message): void` surface, a `NullSmsGateway` that throws, and plumbing so `SmsDriver::dispatch()` (to be
added) resolves the bound gateway.

### A6. Email driver has no delivery path

PRD P0 expects the email driver to dispatch via Laravel's mail subsystem. Currently it only verifies. Need a delivery
path — probably a `Mail\MfaCodeMessage` Mailable that consumers can swap, and a `dispatch($factor)` method on the
driver (or on the manager for consistency with `A3`).

### A7. No lifecycle events

`laravel-authentication` fires standard Laravel auth events alongside custom ones (`PrincipalAssigned`,
`DeviceAuthenticated`, `Refreshed`, `RefreshFailed`). The MFA package fires nothing. Events we should be firing, at
minimum:

- `MfaChallengeIssued` — code generated & delivered (or TOTP challenge presented)
- `MfaVerified` — successful verification
- `MfaVerificationFailed` — wrong/expired/over-limit code (carries a machine-readable reason enum, mirroring
  `RefreshFailureReason`)
- `MfaFactorEnrolled` — new factor registered
- `MfaFactorDisabled` — factor removed/revoked
- `MfaExpired` — optional, can be inferred by consumers from the exception

This also underpins the "audit log" sibling package — without events, `laravel-audit-log` has nothing to observe.

### A8. `getFactors()` return shape leaks implementation

The exception payload is `Collection->toArray()`, which means we ship whatever the consumer's Factor model casts to —
including potentially sensitive columns (`secret`, `code`). This needs a view model / resource (e.g.
`FactorSummary` with `id`, `driver`, `label`, `verified_at`) before the structured exception contract is safe to
document.

### A9. `hasExpired()` returns `true` when `mfa_verified_at` is missing

Semantically defensible ("no verification = expired"), but combined with `MfaRequiredException` (thrown when
`!isSetup()`) and `MfaExpiredException` (thrown when `hasExpired()`), a user who has factors but has never verified
will get `MfaExpiredException`, not `MfaRequiredException`. That's probably the wrong UX — "expired" implies a prior
verification. Needs an explicit `hasNeverVerified()` path or different naming.

---

## Integration story

### Standalone

- Identity model implements `MultiFactorAuthenticatable`.
- App has its own Factor model (or uses the one we ship once `A4` + `Models/` land).
- Verification state lives in the session (default `SessionMfaVerificationStore`).
- Works behind SessionGuard, Sanctum, Passport, custom guards.

### Paired with `sinemacula/laravel-authentication`

- Identity model implements *both* `Identity` (from auth package) and `MultiFactorAuthenticatable` (from this
  package). Both contracts extend `Authenticatable`, so a single model class satisfies both.
- Verification state should live on the `Device` record (`last_mfa_verified_at`) because the paired package is
  stateless. Requires `A1` (storage abstraction) + a `DeviceMfaVerificationStore`.
- The MFA package must **never** import anything from `SineMacula\Laravel\Authentication\*` — the bridge is
  constructed via Laravel's container in `laravel-iam` glue or in the consumer's service provider.

### Wrapped by `sinemacula/laravel-iam`

- Parent package provides: `DeviceMfaVerificationStore` binding, opinionated `OrganisationMfaPolicy` bound against
  the `MfaPolicy` contract, cross-package event listeners (audit log), and any other opinionated defaults.
- This repo stays clean of parent-package knowledge. The extension seams must be expressive enough that the parent
  package doesn't need to monkey-patch.

---

## Code quality observations

### C1. Classes are not `final`

`laravel-authentication` marks every concrete class `final` and uses traits/interfaces for extension. This package
uses plain `class` everywhere. Align with the house style (`final class` + extension via contracts) unless we have a
specific reason to allow subclassing (e.g. `AbstractGuard` equivalent).

### C2. Driver code duplication

`EmailDriver` and `SmsDriver` are ~95% identical. They differ only in the `requiresDelivery()` return (both `true`)
and the class name. After `A4` + `A5` + `A6`, this will become one base class / trait + two thin subclasses that
differ only in their gateway binding.

### C3. Middleware aliases not registered

`MfaServiceProvider` doesn't call `Router::aliasMiddleware('require.mfa', RequireMfa::class)` or similar. Consumers
have to reference the FQCN in their route files. Minor DX issue.

### C4. Facade alias not registered

The facade works via the `mfa` container binding, but no `AliasLoader` entry — so `Mfa::shouldUse()` only works if
the consumer imports the FQN or adds their own alias. Standard Laravel convention in first-party packages is to
register the alias in the service provider.

### C5. `MfaManager::getCachePrefix()` resolves `config` on every call

Minor: read `cache_prefix` once in `boot()` or cache on first access. Low priority.

### C6. `extractRaw` only recognises `\stdClass`

`EmailDriver`/`SmsDriver` `extractRaw` accepts `stdClass` objects via `property_exists` but ignores Eloquent models,
DTOs, or any other object exposing the property. This is a symptom of A4 — after a typed `Factor` contract lands,
the helper goes away.

### C7. No `#[\SensitiveParameter]` on code/secret parameters

`laravel-authentication` annotates passwords/tokens with `#[\SensitiveParameter]` so they're redacted in stack traces.
MFA codes and TOTP secrets deserve the same treatment in `verify()` signatures and driver constructors.

---

## Actionable items

Numbered for easy reference in conversation. Priorities align with PRD P0/P1/P2 where applicable.

| ID   | Priority | Item                                                                                                                                                                                   | Blocks                                                           |
|------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| B-01 | P0       | Introduce `Contracts\MfaVerificationStore` and a default `SessionMfaVerificationStore`                                                                                                 | Standalone JWT; paired mode                                      |
| B-02 | P0       | Add `MfaManager::markVerified()` / `forgetVerification()` surface delegating to the store                                                                                              | A3; PRD state inspection                                         |
| B-03 | P0       | Delete `Contracts/EnforcesMfa.php`; add `Contracts\MfaPolicy` + `Policies\NullMfaPolicy` default                                                                                       | `shouldUse()` correctness                                        |
| B-04 | P0       | Ship `Factor` Eloquent model + migration (ULID PK, polymorphic `authenticatable`, `attempts`, `locked_until`, `last_attempted_at`)                                                     | PRD polymorphic + migrations; supersedes separate attempts model |
| B-06 | P0       | Introduce `Contracts\Factor` interface (typed surface); retype `FactorDriver::verify()` and add `FactorDriver::issueChallenge(Factor): void`                                           | A4; collapses driver duplication                                 |
| B-07 | P0       | Add `Contracts\SmsGateway` + `NullSmsGateway` (fails loud) + fake for tests                                                                                                            | PRD SMS P0                                                       |
| B-08 | P0       | Add manager-level `MfaManager::challenge(string $driver, Factor $factor): void` that dispatches `MfaChallengeIssued` and delegates to the driver's `issueChallenge()` (no-op for TOTP) | PRD email/SMS                                                    |
| B-09 | P0       | Wire email dispatch to Laravel's mail subsystem (swappable `Mailable`)                                                                                                                 | PRD email P0                                                     |
| B-10 | P0       | Implement `BackupCodeDriver` (pure PHP, single-use, constant-time verification)                                                                                                        | PRD backup-code P0                                               |
| B-11 | P0       | Add unified `MfaManager::verify(driver, code, factor)` that orchestrates attempts/events/store                                                                                         | A3                                                               |
| B-12 | P0       | Add lifecycle events (`MfaChallengeIssued`, `MfaVerified`, `MfaVerificationFailed`, enrolment)                                                                                         | Audit log integration                                            |
| B-13 | P0       | Mark concrete classes `final`; expose extension via contracts                                                                                                                          | House style consistency                                          |
| B-14 | P0       | Add middleware aliases + facade alias registration in the service provider                                                                                                             | DX                                                               |
| B-15 | P0       | Tighten exception factor payload to a stable `FactorSummary` shape (no sensitive fields)                                                                                               | A8; structured exceptions PRD                                    |
| B-16 | P0       | Resolve `hasNeverVerified` vs `hasExpired` exception dispatch in `RequireMfa`                                                                                                          | A9; UX correctness                                               |
| B-17 | P0       | Annotate code/secret parameters with `#[\SensitiveParameter]`                                                                                                                          | C7; trace hygiene                                                |
| B-18 | P1       | Add TOTP provisioning URI / QR helper on `TotpDriver`                                                                                                                                  | Enrolment UX                                                     |
| B-19 | P1       | Add configurable alphabet for email/SMS code generation                                                                                                                                | PRD P1                                                           |
| B-20 | P1       | Add step-up middleware variant (accept a shorter expiry override)                                                                                                                      | PRD step-up personas                                             |
| B-21 | P2       | Replay-protect email/SMS codes within their expiry window                                                                                                                              | PRD P2                                                           |
| B-22 | P2       | Document rate-limit patterns for verify endpoints (README + example)                                                                                                                   | PRD P2                                                           |
| B-23 | —        | Add `Contracts\MfaVerificationStore` implementation that reads/writes `Device::last_mfa_verified_at`                                                                                   | Delivered by `laravel-iam` glue                                  |

### Resolved decisions

- **D1 — Policy contract, not `EnforcesMfa`.** The package provides a generic `MfaPolicy` extension seam with a
  no-op default (`NullMfaPolicy`). `EnforcesMfa` is deleted. Consumers bind their own policy (org-aware, role-aware,
  feature-flag-aware). `laravel-iam` ships an opinionated `OrganisationMfaPolicy` at its layer. *(Tracked by B-03.)*
- **D2 — Single `mfa_factors` table.** Columns include `attempts`, `locked_until`, and `last_attempted_at`. No
  separate `mfa_attempts` log — audit goes through events, owned by `laravel-audit-log`. *(Tracked by B-04; former
  B-05 removed.)*
- **D3 — Challenge split between manager and driver.** `MfaManager::challenge()` orchestrates (events, future rate
  limiting, logging). `FactorDriver::issueChallenge(Factor): void` implements per-factor-type transport (no-op for
  TOTP, mail dispatch for email, gateway dispatch for SMS). *(Tracked by B-06 and B-08.)*
- **D4 — Per-device verification is the default.** In paired mode the verification timestamp lives on the `Device`
  record (`last_mfa_verified_at`); in standalone mode it lives on the session (which is already per-device). No
  code change required, but the README must carry a "Security model" note when it next grows: *"MFA verification is
  scoped per device. Verifying on one device does not authorise subsequent access from another."* Step-up middleware
  (B-20) is the escape hatch for "re-verify before this specific action regardless of device state".

---

## Implementation plan

Phased build order. Phases are sequential; items within a phase are mostly parallelisable. Item IDs are stable —
they don't re-number when phases shift.

### Phase 1 — Foundations ✅ complete

Contracts and data shapes with no upstream dependencies. These define the seams every later phase plugs into, so
landing them first avoids rework. All four items are independent and can be split across separate PRs.

- **B-03** ✅ — `MfaPolicy` contract + `NullMfaPolicy` default; deleted `EnforcesMfa`; wired into
  `MfaManager::shouldUse()`.
- **B-04** ✅ — `Factor` Eloquent model + publishable migration (ULID PK, polymorphic `authenticatable`, `attempts`,
  `locked_until`, `last_attempted_at`, `secret`, `verified_at`, `driver`, `label`, `code`, `expires_at`). Migration
  collision guard + `mfa.factor.model` / `mfa.factor.table` config added.
- **B-06** ✅ — `Contracts\Factor` interface with full read surface; `Traits\ActsAsFactor` default implementation;
  retyped `FactorDriver::verify(Factor $factor, string $code)`; added `FactorDriver::issueChallenge(Factor $factor): void`.
  Drivers currently no-op `issueChallenge()` for email/SMS (TODO(B-07) / TODO(B-09)) and TOTP (intentional — TOTP
  challenges are client-side). Removed `requiresDelivery()` (superseded by `issueChallenge()`).
- **B-01** ✅ — `Contracts\MfaVerificationStore` + `Stores\SessionMfaVerificationStore` default bound in the service
  provider. `MfaManager::hasExpired()` still reads the legacy session key directly; migration to the store is
  Phase 2 / B-02.

**Exit criteria met:** all drivers/contracts compile against the new shapes; `composer check` passes (src/ is
clean; only remaining flags are markdown lint on the PRD and the two intentional TODO waypoints on Email/SMS
drivers); `MfaManager::shouldUse()` reads through `MfaPolicy`; no behaviour change beyond the contract swap.

### Phase 2 — Manager orchestration

Now the manager earns its keep. These items depend on Phase 1 contracts and must land together (or very close) so
we don't retrofit events onto an already-shipped orchestrator.

- **B-02** — `MfaManager::markVerified(Authenticatable)` / `forgetVerification(Authenticatable)` delegating to the
  store. Replaces `MfaManager::hasExpired()`'s hard-coded session read.
- **B-12** — Lifecycle events (`MfaChallengeIssued`, `MfaVerified`, `MfaVerificationFailed`, `MfaFactorEnrolled`,
  `MfaFactorDisabled`) + a `MfaVerificationFailureReason` enum mirroring the auth package's
  `RefreshFailureReason` pattern. Land *with* B-11 / B-08 so dispatch sites are created once.
- **B-08** — `MfaManager::challenge(string $driver, Factor $factor): void` — dispatches `MfaChallengeIssued`, calls
  `$driver->issueChallenge($factor)`.
- **B-11** — `MfaManager::verify(string $driver, string $code, Factor $factor): bool` — dispatches `Attempting`
  analogue, runs the driver, increments `attempts` / sets `locked_until` on failure, dispatches `MfaVerified` or
  `MfaVerificationFailed`, calls `markVerified()` on success.

**Exit criteria:** a consumer can drive the full challenge → verify → markVerified lifecycle through the manager
facade; every branch dispatches an event; `hasExpired()` reads through the store.

### Phase 3 — Drivers on the new shape

Drivers get real transport. Each driver is an independent deliverable once Phase 2 lands.

- **TOTP migration** *(part of B-06 cleanup)* — `TotpDriver::verify()` now reads `$factor->getSecret()` instead of
  sniffing `stdClass`. `issueChallenge()` stays a no-op.
- **B-07** — `Contracts\SmsGateway` + `Gateways\NullSmsGateway` (throws with a "bind your own" message) + a
  `FakeSmsGateway` for tests. Service provider binds the null default.
- **SMS driver rewrite** *(folds into B-06 + B-07)* — `SmsDriver` becomes thin: generates a code, persists it on
  the factor, dispatches through the bound `SmsGateway` in `issueChallenge()`, verifies via `hash_equals` in
  `verify()`.
- **B-09** — `EmailDriver::issueChallenge()` dispatches a swappable `Mail\MfaCodeMessage` Mailable through Laravel's
  mail subsystem. Code generation matches the SMS path.
- **B-10** — `BackupCodeDriver` (pure PHP). Generates N single-use codes at enrolment, stores hashed, marks
  consumed on verification. `issueChallenge()` is a no-op (codes are pre-issued). `generateSecret()` returns the
  code set.

**Exit criteria:** all four built-in drivers implement the full contract; `EmailDriver`/`SmsDriver` share an
abstract base or trait so the duplication from C2 is gone.

### Phase 4 — Middleware & exception polish

Nothing here is hard — but B-15 depends on `FactorSummary` which depends on the Factor model from Phase 1, and
B-16 needs the store-based `hasExpired()` from Phase 2 to make the right decision.

- **B-15** — Replace `->toArray()` payload on the exceptions with a `FactorSummary` value object (`id`, `driver`,
  `label`, `verified_at`). Never leak `secret` / `code` / `attempts`.
- **B-16** — `RequireMfa` currently throws `MfaExpiredException` when `mfa_verified_at` is absent. Split the
  decision: no factors → `MfaRequiredException`; factors exist but never verified → `MfaRequiredException` (not
  "expired"); factors exist + prior verification aged out → `MfaExpiredException`. Add
  `MfaManager::hasEverVerified()` to drive the split.
- **B-14** — Register `require.mfa` / `skip.mfa` middleware aliases in `MfaServiceProvider::boot()`; register the
  `Mfa` facade alias via `AliasLoader`.

**Exit criteria:** consumers can attach `'require.mfa'` in their route files; exception payloads are documented and
safe to serialise; the "never verified" UX matches the "expired" UX.

### Phase 5 — Hygiene pass

Mechanical cleanups done last so no earlier phase has to step around them. All items are low-risk and can be a
single PR.

- **B-13** — Mark every concrete class `final` unless it's an explicit extension point. Align with the
  authentication package's house style.
- **B-17** — `#[\SensitiveParameter]` on every `$code`, `$secret`, and `$password` in driver / manager signatures
  and constructors.
- **Static analysis sweep** — one pass at PHPStan level 8 fixing any errors accumulated across earlier phases (the
  user flagged this as an acceptable end-of-build step).

**Exit criteria:** `composer check` is clean; no concrete class is unnecessarily open; stack traces don't leak
codes or secrets.

### Phase 6 — P1 enhancements

Genuine PRD P1 features, now that P0 is closed. Can be split and shipped independently.

- **B-18** — TOTP provisioning URI / QR helper on `TotpDriver`. Makes enrolment turnkey for consumers.
- **B-19** — Configurable alphabet + length for email/SMS/backup-code generation.
- **B-20** — Step-up middleware variant (`RequireFreshMfa` or similar) that accepts an expiry override, ignoring
  the stored timestamp when shorter than the override. This is the escape hatch behind D4.

### Phase 7 — P2 nice-to-haves

Small, optional, non-blocking.

- **B-21** — Replay-protect consumed email/SMS codes within their expiry window.
- **B-22** — README/docs: rate-limit recipe for verify endpoints using Laravel's `RateLimiter`.

### Phase 8 — External (delivered by `laravel-iam`)

Not this repo's work, tracked for visibility.

- **B-23** — `DeviceMfaVerificationStore` in `laravel-iam` glue that reads/writes
  `Device::last_mfa_verified_at` via the authentication package's contract. This is what unlocks paired-mode
  stateless operation for consumers of the parent package.

### Phase 9 — Test suite (release gate)

**100% line coverage is the release gate.** All other phases must be complete before this one lands, because the
test suite pins the observable contract of the package. Split across the four configured suites:

- **B-T1** — `tests/Unit/` — per-class unit tests covering every public method, every driver branch, every
  contract implementation, and every exception path.
- **B-T2** — `tests/Feature/` — end-to-end lifecycle tests: challenge → verify → markVerified → middleware pass;
  challenge → verify fail → attempt increment → lockout; expired challenge rejection; policy-driven enforcement;
  never-verified vs. expired exception dispatch.
- **B-T3** — `tests/Integration/` — middleware against at least three auth stacks (SessionGuard, Sanctum, custom
  `Authenticatable`); fresh-DB migration run on SQLite + MySQL + PostgreSQL; custom driver extension via
  `Mfa::extend()`; custom Factor model binding via config.
- **B-T4** — `tests/Performance/` — query and write budget assertions on the verify hot path (target: 0 queries
  beyond factor resolution; 1 update on successful verify; 0 updates on TOTP verify); lockout path budget;
  middleware budget when MFA is off.
- **B-T5** — `benchmarks/` — PHPBench benches for the verify hot paths (TOTP, email, SMS, backup) and the
  challenge issuance path; baseline on merge so regressions are visible on the next benchmark run.
- **B-T6** — `infection.json5` scope refinement — keep the current wide exclusion list until the test suite is
  in place, then prune it so the P0 logic (drivers, manager orchestration, policy evaluation, store operations,
  exception dispatch) meets the 85% MSI gate. The wider `infection.full.json5` suite stays gate-less for visibility.

**Exit criteria:** `composer test:coverage` reports 100% line coverage on `src/`; `composer test:mutation` passes
the 85% MSI gate; `composer test:performance` green against the committed budgets; `composer bench:ci` produces
baseline output with no regressions vs. the first committed baseline.

---

### Suggested first PR boundaries

If we split Phase 1 into PRs, a reasonable cut:

- **PR 1:** B-03 (policy contract) — smallest, lowest risk, unblocks `shouldUse()` without touching drivers.
- **PR 2:** B-04 (factor model + migration) + B-06 (Factor contract + driver signature change) — land together
  because the driver signature change is only meaningful once a typed factor exists.
- **PR 3:** B-01 (verification store contract + session implementation). Independent of the factor work.

Phase 2 is best landed as a single PR because B-02/B-08/B-11/B-12 all touch the manager and share event dispatch
sites. Phase 3 is three PRs (one per non-TOTP driver). Phases 4–7 are small enough to batch however convenient.
