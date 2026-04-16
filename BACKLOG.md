# Backlog

Forward-looking work tracked against the road to `sinemacula/laravel-mfa` 1.0 and the first patch
release.

The git log is the audit trail for everything already shipped — this file lists what *remains*.
Entries are grouped by release, with the resolved-architecture / out-of-scope sections kept as
durable context for new contributors and the wider IAM glue.

---

## Status

- **323 tests / 846 assertions** passing across Unit / Feature / Integration / Performance suites.
- **100% line / method / class coverage** on `src/` (518/518 statements, 131/131 methods, 26/26
  classes).
- **Mutation gate green** — 100% Mutation Code Coverage, 91% Covered MSI on scoped paths (gate:
  85%; goal: 90%).
- **PHPBench benchmarks** covering every hot-path (TOTP, OTP, backup codes, FactorSummary).
- **`composer check -- --all --no-cache`** exits 0 across the whole repo. No `[[triage]]` rule
  suppressions in `.qlty/qlty.toml`; the three `@SuppressWarnings("php:S1448")` annotations in
  test fixtures are justified by the `Factor` / `EloquentFactor` contract surfaces.

The 1.0 candidate sits on `feature/release-1.0-prep`. A pre-handoff review on `4878979` surfaced
five blockers that must land before tagging. They are listed under **Release blockers** below.

---

## Release blockers (must land before 1.0 tag)

### B-24 — Real Sanctum integration test

**Why:** PRD P0 "Standalone integration" acceptance criterion explicitly requires integration tests
against **SessionGuard, Sanctum, AND a custom guard**. `tests/Integration/MultiAuthStackTest.php`
currently exercises SessionGuard, a hand-rolled "token-style" `Guard` impl, and a `GenericUser`
custom guard — but not Sanctum's actual `auth:sanctum` driver. An external reviewer will read the
PRD and grep for `Sanctum` in tests.

**Files to touch:**

- `composer.json` — add `laravel/sanctum` to `require-dev`.
- `tests/Integration/MultiAuthStackTest.php` — add a fourth case using `auth:sanctum` against a
  `HasApiTokens`-using identity.
- `tests/Fixtures/TestUser.php` (or a sibling) — make sure the test user satisfies Sanctum's
  `HasApiTokens` trait if added.

**Exit criteria:** test green; `composer check` clean; coverage on `src/` stays at 100%.

---

### B-25 — Remove or document the unused `MfaFactorEnrolled` / `MfaFactorDisabled` events

**Why:** `src/Events/MfaFactorEnrolled.php` and `src/Events/MfaFactorDisabled.php` exist with full
docblocks ("fires after factor record has been persisted", "fires after factor is disabled") but
are **never dispatched** anywhere in `src/`. Confirmed via grep — only the event-DTO unit tests
reference them. Consumers will subscribe to them expecting them to fire; they never will.

**Decision required:** ship a real enrolment / disable API in 1.0, or remove the events.

**Recommended:** remove for 1.0. The package has no enrolment or disable API — the README tells
consumers to call `Factor::create(...)` and `$factor->delete()` directly. Re-introduce events when
an enrolment API ships.

**Files to touch:**

- Delete `src/Events/MfaFactorEnrolled.php` and `src/Events/MfaFactorDisabled.php`.
- Delete `tests/Unit/Events/MfaFactorEnrolledTest.php` and
  `tests/Unit/Events/MfaFactorDisabledTest.php`.
- Search the repo for any remaining references and clean up.

**Exit criteria:** `composer test` green; mutation gate stays green; nothing in the public surface
references the removed classes.

---

### B-26 — README "Identity model setup" snippet uses non-existent class

**Why:** README "Identity model setup" example uses `AuthFactor::class` in
`$this->morphMany(AuthFactor::class, 'authenticatable')`. The shipped model is
`SineMacula\Laravel\Mfa\Models\Factor`. Copy-pasted into a new app, this fatal-errors at boot.

**Files to touch:**

- `README.md` — change `AuthFactor::class` to `\SineMacula\Laravel\Mfa\Models\Factor::class` in the
  identity-model snippet (look around line 175).

**Exit criteria:** snippet compiles when copy-pasted into a fresh Laravel app.

---

### B-27 — README "Extensibility" table references non-existent contract

**Why:** README "Extensibility" table lists `EnforcesMfa` as the contract for "Organisation
enforcement". No such contract exists — the contract is `MfaPolicy` (per resolved decision D1).
Misleading for consumers reading the table to find their extension point.

**Files to touch:**

- `README.md` — replace `Implement EnforcesMfa on your organisation model` with `Implement
  MfaPolicy and bind it via the container`. While there, tighten the "Custom factor model" cell to
  `Set config('mfa.factor.model') to your subclass.`

**Exit criteria:** table accurately reflects the public extension surface.

---

### B-28 — Populate `CHANGELOG.md` for 1.0

**Why:** `CHANGELOG.md` `[1.0.0] - Unreleased` block is empty. A 1.0 tag with no changelog is a bad
signal to consumers.

**Files to touch:**

- `CHANGELOG.md` — populate the 1.0.0 block with the high-level feature list (four built-in
  drivers, middleware, structured exceptions, polymorphic identity support, configurable code
  alphabet, step-up middleware, rate-limit recipe, Twilio gateway example, etc).

**Exit criteria:** changelog reads well to a consumer who has never seen the package.

---

## 1.0.1 polish (recommended for the next patch)

Findings from the pre-handoff review that are not release blockers but are worth shipping in the
first patch.

### B-29 — Pin the consumer-override invariant on built-in drivers

**Why:** Commit `4878979` moved built-in driver factories from `MfaManager::createXDriver()` into
`MfaServiceProvider::registerBuiltInDrivers()` via Laravel's `extend()` API. This is the right
idiom — but the existing `tests/Integration/CustomDriverExtensionTest.php` only exercises NEW
driver names. There is no test asserting that `Mfa::extend('totp', ...)` from a consumer service
provider, booted AFTER the package's provider, actually overrides the built-in TOTP driver.

**Files to touch:**

- `tests/Integration/CustomDriverExtensionTest.php` — add `testConsumerCanOverrideBuiltInTotpDriver`:
  register a fake driver via `Mfa::extend('totp', ...)`, resolve `Mfa::driver('totp')`, assert the
  fake instance is returned.

**Exit criteria:** test green; pins the override behaviour against future Laravel `Manager`
upgrades.

---

### B-30 — Encrypt the OTP `code` column at rest

**Why:** The `Factor::$secret` column carries an `encrypted` cast (TOTP secrets, backup-code
hashes); the `Factor::$code` column does not. `code` holds a live cleartext one-time code at rest
until expiry/use. An attacker with read-only DB access can replay a freshly-issued SMS or email
code within its expiry window. Asymmetric defence-in-depth.

**Files to touch:**

- `src/Models/Factor.php` — add `code` to `$casts` with the `encrypted` cast.
- `database/migrations/2026_04_15_000000_create_mfa_factors_table.php` — widen the `code` column
  from a fixed length to `text` so encrypted ciphertext fits.
- Tests that assert `code` round-trips correctly.

**Exit criteria:** `Factor` round-trips a stored code through the encryption layer; existing tests
still pass; mutation gate stays green.

---

### B-31 — Fix `BackupCodeDriver` class docblock RNG claim

**Why:** `src/Drivers/BackupCodeDriver.php` class docblock claims "Generation uses `random_bytes`
for cryptographic suitability." The implementation actually uses `random_int` (line 245). Both are
CSPRNG-grade, so this is documentation drift, not a security regression — but it will mislead a
reviewer reading the docblock.

**Files to touch:**

- `src/Drivers/BackupCodeDriver.php` — update the class docblock to read "Generation uses
  `random_int` over the configured alphabet."

**Exit criteria:** docblock matches implementation.

---

### B-32 — Kill the surviving boundary mutants in `FactorSummary` and `MfaManager::hasExpired`

**Why:** Mutation report shows two pockets of survivors:

- `Support/FactorSummary::maskEmail()` mutants 35–39: `explode($, $, 1)`/`3`, `min(2, …)`/`min(3,
  …)`, `floor`→`ceil`/`round`. The mask logic is under-asserted — a regression that returns
  `*@example.com` instead of `ab*****@example.com` would not be caught.
- `MfaManager::hasExpired()` mutants 24/25: swap `$elapsed < 0` ↔ `<= 0` and `$elapsed > $window`
  ↔ `>= $window`. The expiry test uses `subMinutes(120)` vs `60` (a wide gap) and never tests the
  exact-boundary case.

**Files to touch:**

- `tests/Unit/Support/FactorSummaryTest.php` — add cases for one-character local-part (`a@x.com`),
  two-character local-part (`ab@x.com`), and a long local-part — assert the exact masked output.
- `tests/Unit/MfaManagerExpiryTest.php` — add `testHasExpiredReturnsFalseAtExactBoundary` (e.g.
  `subMinutes(60)` against `window=60` should still be valid) and
  `testHasExpiredReturnsTrueOneMinuteAfterBoundary`. Pins the inclusive/exclusive semantics for
  consumers.

**Exit criteria:** Mutation gate Covered MSI rises (target: ≥93%); both mutant clusters killed.

---

## Future improvements (deferred — judgement-call polish)

Lower-severity findings from the same review. Not blocking 1.0 or 1.0.1, but worth a sweep in a
later release.

- **B-33 — CI matrix verification.** PRD success criteria claims migrations green on SQLite +
  MySQL + PostgreSQL. Confirm `.github/workflows/tests.yml` actually runs the matrix; if not, add
  it. (May already be configured — needs inspection.)
- **B-34 — `MfaServiceProvider::registerBuiltInDrivers()` should use `static::` for late binding.**
  Currently `self::`, which prevents subclasses of the provider from overriding it without
  touching the singleton closure. Either drop `static` (and use `$this->`) or change `self::` to
  `static::`.
- **B-35 — Validate `:code` placeholder in SMS template at construction.** `SmsDriver::dispatch`
  uses `str_replace(':code', $code, $template)` — silently sends a literal `Your verification
  code is: :code` if the developer typoed the template. Assert presence in the constructor and
  throw `InvalidArgumentException` on mismatch.
- **B-36 — Document the `Mfa::driver()` resolution-cache caveat.** Laravel's `Manager` caches
  resolved drivers per request. If a consumer calls `Mfa::driver('totp')` (e.g. eager during boot)
  before their own provider calls `Mfa::extend('totp', ...)`, the override silently fails. README
  should mention "Register your override before any code calls `Mfa::driver(...)` — Laravel's
  manager caches resolved drivers per request."
- **B-37 — Document the session-regenerate assumption on `SessionMfaVerificationStore`.** Add a
  one-liner to the class docblock: "Assumes consumers regenerate the session on auth state change
  (Laravel's default); apps that disable that should also call `Mfa::forgetVerification()` on
  login."
- **B-38 — Defend the rate-limit recipe `null`-key edge.** README recipe uses `(string)
  $identifier` — when both `$request->user()` and `$request->ip()` return null, every
  unauthenticated request shares one bucket keyed `""`. Mirror the `?? 'unknown'` defence on the
  per-identity limit too.
- **B-39 — Clean up redundant `is_int` arm in `MfaManager::resolveIntConfig`.** Dead in practice
  — `is_numeric($value)` returns true for any int and `(int) $value` is identity for ints.
  Either delete the arm or add a test asserting an `int` value flows through unchanged (e.g.
  `PHP_INT_MAX`).
- **B-40 — Tighten `FactorDriver::generateSecret()` contract docblock.** Currently disagrees with
  `BackupCodeDriver::generateSecret()` (which returns a plaintext code, not null). Update the
  contract to say "returns the seed material the driver uses for fresh enrolment — TOTP secret,
  single backup code, or `null` for OTP drivers that mint codes per challenge."
- **B-41 — Optional: collapse the three `@SuppressWarnings("php:S1448")` annotations.** Extract a
  shared `tests/Fixtures/AbstractFactorStub.php` abstract class implementing the boilerplate
  `Factor` getters; have the three anonymous classes extend it. Drops three triages, costs one
  fixture file. Quality-of-life only.
- **B-42 — Document `APP_KEY` rotation in README "Configuration".** `Factor::$secret` is encrypted
  at rest; a malformed key rotation will yield un-decryptable rows. One-line README footnote on
  the `php artisan key:rotate` workflow would close the loop for ops teams.

---

## Architecture reference

The package is designed to operate cleanly in three modes. Any new work must keep all three
working.

### Standalone

- Identity model implements `MultiFactorAuthenticatable`.
- Default `SessionMfaVerificationStore` keeps verification state in the session (per-device by
  construction).
- Works behind SessionGuard, Sanctum, Passport, or any custom guard whose `Auth::user()` returns
  a `MultiFactorAuthenticatable`.

### Paired with `sinemacula/laravel-authentication`

- The same identity model implements both `Identity` (from the auth package) and
  `MultiFactorAuthenticatable` (from this package). Both contracts extend Laravel's standard
  `Authenticatable`, so a single class satisfies both.
- Verification state should live on the `Device` record (`last_mfa_verified_at`) because the auth
  package is stateless. The seam is the `MfaVerificationStore` contract — paired-mode apps rebind
  it. This package must **never** import anything from `SineMacula\Laravel\Authentication\*`; the
  bridge is constructed in the consumer's service provider or in the `laravel-iam` glue.

### Wrapped by `sinemacula/laravel-iam`

- Parent package provides: a `DeviceMfaVerificationStore` binding (B-23, out of repo), an
  opinionated `OrganisationMfaPolicy` bound against the `MfaPolicy` contract, cross-package event
  listeners (audit log), and any other opinionated defaults.
- This repo stays clean of parent-package knowledge. The extension seams (policy, store, gateway)
  must be expressive enough that the parent package does not need to monkey-patch.

---

## Resolved decisions

Historical record of the architectural calls made during the foundation phases. Anything new
should be consistent with these unless explicitly discussed.

- **D1 — Generic `MfaPolicy` contract, not org-specific `EnforcesMfa`.** The package ships a
  `MfaPolicy` extension seam with a no-op default (`NullMfaPolicy`). Consumers bind their own
  policy (org-aware, role-aware, feature-flag-aware). `laravel-iam` ships an opinionated
  `OrganisationMfaPolicy` at its layer. The MFA package never learns the word "organisation".
- **D2 — Single `mfa_factors` table.** Columns include `attempts`, `locked_until`,
  `last_attempted_at`, `verified_at`. No separate `mfa_attempts` log — audit goes through events,
  owned by `laravel-audit-log`.
- **D3 — Challenge split between manager and driver.** `MfaManager::challenge()` orchestrates
  (events, rate-limiting hooks, logging). `FactorDriver::issueChallenge(Factor): void` implements
  per-factor-type transport (no-op for TOTP, mail dispatch for email, gateway dispatch for SMS,
  no-op for backup codes since they are pre-issued).
- **D4 — Per-device verification is the default.** In paired mode the verification timestamp
  lives on the `Device` record; in standalone mode it lives on the session (which is already
  per-device). The step-up middleware (`mfa:N`) is the escape hatch for "re-verify before this
  specific action regardless of device state".
- **D5 — Built-in driver factories live in the service provider.** As of `4878979`, the four
  shipped drivers (TOTP, email, SMS, backup codes) are registered against the manager via the
  standard `Mfa::extend(...)` API from `MfaServiceProvider::registerBuiltInDrivers()`. This makes
  built-in drivers indistinguishable from consumer-registered ones, which is what the three-mode
  story needs. Consumer overrides via `Mfa::extend()` work because Laravel's `Manager` resolves
  the most-recent registration. (Test pinning this invariant: B-29.)
- **D6 — Radarlint S1142 / S1448 thresholds align with the build:enforce pack, not radarlint
  defaults.** The `/build:enforce` PHP language pack governs cyclomatic complexity, method length,
  nesting depth and signature length — but does not enforce a max-returns-per-method or
  max-methods-per-class. Where the contract surface forces an unavoidable method count (anonymous
  classes implementing `Factor` / `EloquentFactor`), the test fixtures carry an explicit
  `@SuppressWarnings("php:S1448")` annotation with a one-paragraph justification. The
  `.qlty/qlty.toml` itself stays free of `[[triage]]` rule suppressions.

---

## Out of scope (delivered by `sinemacula/laravel-iam`)

Not this repo's work, tracked here for visibility so the IAM glue's authors know what to wire.

### B-23 — `DeviceMfaVerificationStore`

A `MfaVerificationStore` implementation that reads / writes the `last_mfa_verified_at` column on
the `Device` record from `sinemacula/laravel-authentication`. This is what makes paired-mode
(stateless JWT, Sanctum personal access tokens, Passport) verification persist *per device*
instead of leaning on the session — without it the default `SessionMfaVerificationStore` cannot
work for stateless stacks.

Lives in `laravel-iam` because that package is the only one allowed to depend on both
`laravel-mfa` and `laravel-authentication`. Shape of the integration:

```php
// In laravel-iam's service provider:
$this->app->singleton(MfaVerificationStore::class, DeviceMfaVerificationStore::class);
```

```php
// laravel-iam/src/Stores/DeviceMfaVerificationStore.php
final readonly class DeviceMfaVerificationStore implements MfaVerificationStore
{
    public function __construct(private AuthManager $auth) {}

    public function markVerified(Authenticatable $identity, ?CarbonInterface $at = null): void
    {
        $device = $this->auth->guard()->device(); // contextual accessor on the auth package
        if ($device instanceof EloquentDevice) {
            $device->forceFill(['last_mfa_verified_at' => $at ?? now()])->save();
        }
    }

    public function lastVerifiedAt(Authenticatable $identity): ?CarbonInterface
    {
        return $this->auth->guard()->device()?->getLastMfaVerification();
    }

    public function forget(Authenticatable $identity): void
    {
        $device = $this->auth->guard()->device();
        if ($device instanceof EloquentDevice) {
            $device->forceFill(['last_mfa_verified_at' => null])->save();
        }
    }
}
```

The MFA package's `MfaVerificationStore::markVerified()` accepts an optional `CarbonInterface $at`
precisely so this implementation can stamp the device row atomically with the verification event.

---

## Shipped

Quick index of the major work that has already landed (full audit trail in `git log`):

- **B-18** ✅ TOTP provisioning URI helper — `7be3199`
- **B-19** ✅ Configurable code alphabet — `c9f6545`
- **B-20** ✅ Step-up middleware via parameterised `mfa:N` — `83b463f`, hardened in `ec83773`
- **B-22** ✅ Rate-limit recipe in README — `8ffcda1`
- **PRD P1** ✅ Documented Twilio `SmsGateway` binding example — `a2b48ef`
- **Refactor** ✅ MfaManager surface trimmed to ≤20 methods, ≤3 returns; built-in driver factories
  moved to `MfaServiceProvider` via `extend()` — `4878979`
