# Backlog

Findings from the independent pre-handoff review (`ISSUES.md`) that need to land before the
1.0 tag. Every entry below has been re-verified against the current branch — these are not
speculative; the file/line references confirmed.

Items are listed in execution order: security blockers first, then correctness, then docs.

Durable architectural context lives in `docs/ARCHITECTURE.md`; this file is the actionable list.

---

## B-43 — Reject cross-account factor use at the package boundary

**Severity:** Blocker (security — MFA bypass / factor-tampering primitive)

**Why:** `MfaManager::verify()`, `challenge()`, `enrol()`, and `disable()` all accept an
arbitrary `Factor` instance and never check it against the current identity. `verify()` then
calls `$store->markVerified($identity)` against the *current* identity (`src/MfaManager.php:510`),
not the factor's owner. A consumer building the natural endpoint shape ("look up factor by ID
from the request, call `Mfa::verify(...)`") gives an attacker who has compromised account B's
session — but who has their own account A's MFA — a free pass: submit the A-owned factor with
a code A can generate, and B is marked verified.

The same trust gap lets a caller challenge or disable any factor in the database, regardless of
ownership.

**Files to touch:**

- `src/MfaManager.php` — guard `challenge()`, `verify()`, and `disable()` with a private
  `assertFactorBelongsToIdentity(Factor, MultiFactorAuthenticatable): void` helper that throws
  (a new dedicated exception, e.g. `FactorOwnershipMismatchException`) when the factor's
  authenticatable type/id don't match the current identity. For non-Eloquent `Factor`
  implementations (no morph columns), require the factor's `getAuthenticatable()` to be the
  same instance / equal by identifier.
- `src/MfaManager.php` — `enrol()` must stamp the current identity onto the factor's morph
  columns itself, never trust the caller-supplied values (overwrite if present so consumers
  cannot enrol a factor against another account).
- `src/Exceptions/FactorOwnershipMismatchException.php` — new exception, extends a sensible
  parent so consumers can catch it cleanly.
- `tests/Unit/MfaManagerVerifyTest.php` / `MfaManagerChallengeTest.php` /
  `MfaManagerLifecycleTest.php` — regression tests: same scenario for each entry point,
  asserting the exception fires when `Auth::user()` is identity B but the supplied factor
  belongs to identity A.
- `README.md:165-180` — clarify the enrolment paragraph: factor morph columns are managed by
  the package, not by the consumer. Update the worked example.

**Exit criteria:** new exception type covered (line + branch); 100% coverage retained;
`composer check` clean; existing tests still green.

---

## B-44 — Stop `challenge()` from clearing TOTP / backup-code lockouts

**Severity:** High (security — bypasses the configured `max_attempts` for non-OTP drivers)

**Why:** `MfaManager::challenge()` runs `$factor->resetAttempts()` on every `EloquentFactor`
before invoking the driver (`src/MfaManager.php:298-299`). That's correct for email / SMS where
a brand-new code is minted in `issueChallenge()`. But `TotpDriver::issueChallenge()` and
`BackupCodeDriver::issueChallenge()` are no-ops (TOTP codes are app-side, backup codes are
pre-issued at enrolment) — so calling `challenge()` on a locked TOTP factor wipes the lockout
without rotating any secret material. Any "resend code" or "start MFA" endpoint becomes a
free unlock.

**Files to touch:**

- `src/Drivers/AbstractOtpDriver.php` — call `$factor->resetAttempts()` inside `issueChallenge()`
  *after* the new code has been generated and dispatched (so a fresh code accompanies the reset).
- `src/MfaManager.php:298-299` — remove the unconditional `resetAttempts()` from the manager
  preamble; it now lives where it belongs.
- `tests/Feature/TotpLifecycleTest.php` (or new sibling) — regression test:
  1. Lock a TOTP factor by submitting `max_attempts` wrong codes.
  2. Call `Mfa::challenge('totp', $factor)`.
  3. Assert the factor is still locked.
- Same regression shape for `BackupCodeDriver`.

**Exit criteria:** lockout regression test added and passing; existing email/SMS lifecycle tests
still green; mutation gate stays ≥85% MSI.

---

## B-45 — Make the MySQL / PostgreSQL CI matrix actually run

**Severity:** High (release-criterion violation — false-green badge)

**Why:** `tests/TestCase.php:53-58` and `tests/Unit/MfaManagerTestCase.php:56-61` unconditionally
overwrite `database.connections.testing` to in-memory SQLite — even when CI has provisioned
MySQL / PostgreSQL and exported `DB_CONNECTION` / `DB_*` env vars
(`.github/workflows/tests.yml:88-147`). The "database-tests" matrix is currently exercising
SQLite three times, not three engines. Engine-specific schema or query bugs ship behind a
green badge.

**Files to touch:**

- `tests/TestCase.php` (and `tests/Unit/MfaManagerTestCase.php` if needed) — only force
  in-memory SQLite when no `DB_CONNECTION` env var is set; otherwise honour the env-driven
  config (`driver`, `host`, `port`, `database`, `username`, `password`) so the workflow's
  provisioned engines actually back the connection.
- `.github/workflows/tests.yml` — sanity-check: a step that runs `php -r "echo
  config('database.default');"` (or equivalent) to log the resolved driver, so a future
  regression is loud in CI output.
- Optional but recommended: a dedicated migration smoke test
  (`tests/Database/MigrationSmokeTest.php`) that runs the package migration end-to-end and
  asserts the resulting columns / indexes match expectations. This is the test that catches
  engine-specific failures.

**Exit criteria:** `composer test` passes locally against SQLite; CI matrix passes against
MySQL + PostgreSQL with the new harness; migration smoke test green on all three.

---

## B-46 — Fix the README copy-paste-fatal examples

**Severity:** Medium (consumer onboarding — paste-and-fatal)

**Why:** Three concrete bugs in the worked examples a new consumer will copy first:

- `README.md:162` calls `$driver->verify($code, $factor)` — argument order reversed; real
  signature is `verify(Factor $factor, string $code)`. Pasting fatals with `TypeError`.
- `README.md:318` shows `isMfaEnabled()` querying a `verified` boolean column. The column does
  not exist — the model uses `verified_at` (datetime).
- `README.md:321` declares `authFactors(): \Illuminate\Contracts\Database\Eloquent\Builder` —
  the contract uses the concrete `\Illuminate\Database\Eloquent\Builder`. The interface
  reference returns a different shape and won't satisfy the contract.

**Files to touch:**

- `README.md` — fix all three. While we're there, change the hardcoded
  `\SineMacula\Laravel\Mfa\Models\Factor::class` reference in the snippet to use the helper
  introduced by **B-48** (`Mfa::factorModel()`), so the worked example actually exercises the
  configurable seam.

**Exit criteria:** snippet pastes cleanly into a fresh Laravel app and the model satisfies
`MultiFactorAuthenticatable` without further fixes.

---

## B-47 — Scope the runtime cache key by identity class

**Severity:** Medium (correctness — polymorphic state bleed)

**Why:** `MfaManager::getCachePrefix()` (`src/MfaManager.php:632-645`) builds the key from only
the auth identifier, not the identity class. `User #1` and `Admin #1` share the same cache
entry within a request. The polymorphic-identity test had to call `Mfa::clearCache()` between
identity switches — that's the smoking gun. The package advertises polymorphic identity
support as a strength; the cache layer breaks it.

**Files to touch:**

- `src/MfaManager.php` — include the identity's morph class (or, for non-Eloquent
  `Authenticatable`, the FQCN) in the cache key. Suggested shape:
  `mfa:{morphClassOrFqcn}:{identifier}:` so `mfa:App\User:1:setup` and `mfa:App\Admin:1:setup`
  are distinct.
- `tests/Integration/PolymorphicIdentityTest.php` — drop the manual `Mfa::clearCache()` calls
  between identity switches; the new key shape should make them unnecessary. Add a regression
  test that exercises both identities back-to-back with the same primary key without manual
  clearing.

**Exit criteria:** regression test green without manual cache clearing; existing tests stay
green; coverage retained.

---

## B-48 — Make `mfa.factor.model` a real seam (not dead config)

**Severity:** Medium (public API / documentation breach — PRD acceptance criterion unmet)

**Why:** `config/mfa.php:23` exposes `mfa.factor.model`, the changelog and README both promise
it, and the PRD's "Customisable factor and attempt models" acceptance criterion explicitly
requires "configuration values are read at boot to resolve factor and attempt models" used by
"all package internals". Today nothing reads it — a repo grep finds the key only in config
and docblocks. Setting `MFA_FACTOR_MODEL=App\MyFactor` does nothing.

**Files to touch:**

- `src/MfaManager.php` — add a public `factorModel(): string` accessor that reads
  `config('mfa.factor.model')` and returns the class string. Validate it's a class implementing
  `EloquentFactor` (throw a dedicated exception if not — likely `MissingDriverDependencyException`-
  style).
- `src/Facades/Mfa.php` — `@method static string factorModel()` so `Mfa::factorModel()` works
  off the facade.
- `README.md` — the "Identity model setup" snippet uses `Mfa::factorModel()` in the
  `morphMany(...)` call so the configurable seam is exercised by the worked example.
- `tests/Integration/CustomFactorModelTest.php` (new) — define a custom subclass of `Factor`,
  bind it via config, enrol/verify against it, assert the package returns instances of the
  custom class throughout (manager `getFactors()`, lifecycle events, etc.).

**Exit criteria:** custom model integration test green; `Mfa::factorModel()` covered;
`composer check` clean.

---

## B-49 — Ship a first-party backup-code issuance / rotation API

**Severity:** Medium (security-sensitive consumer hand-roll)

**Why:** The driver exposes primitives — `generateSet()` returns plaintext codes,
`hash($code)` hashes one — but the package provides no manager-level API to issue a fresh
batch to the current identity, atomically replace any existing batch, or revoke old codes
during regeneration. Each consumer hand-rolls the delete-and-reissue, the transaction
boundary, the plaintext-only-once guarantee, and the cache invalidation. Backup codes are the
package's own recovery factor — the workflow should not be left to chance.

**Files to touch:**

- `src/MfaManager.php` — add a public method
  `issueBackupCodes(?int $count = null): array<int, string>`:
  1. Resolve current identity (no-op + return `[]` if no identity).
  2. Inside a transaction: delete every existing `backup_code` factor for the identity, mint a
     fresh set via `BackupCodeDriver::generateSet()`, persist each as a `Factor` row with the
     hashed value on `secret`.
  3. Clear the manager cache for the identity.
  4. Dispatch `MfaFactorEnrolled` for each new factor (so audit logs and any other subscribers
     see the rotation as a normal lifecycle event).
  5. Return the plaintext list exactly once for the caller to display / download.
- This pushes the manager method count to 21 — collapse `applyVerificationOutcome` into
  `verify()` or split its lockout-application step into a tiny private helper that already
  exists. Confirm the count stays ≤20.
- `tests/Unit/MfaManagerLifecycleTest.php` — coverage: no-identity no-op; rotation deletes
  prior set; rotation persists hashed values only; rotation dispatches one
  `MfaFactorEnrolled` per new code; cache invalidates.
- `README.md` — backup-code section under "Enrolment and disable" with the worked example,
  alongside the existing TOTP and SMS sections.

**Exit criteria:** issuance test exercises every branch; manager method count ≤20; coverage
stays at 100% on `src/`; mutation gate stays ≥85% MSI.

---

## B-50 — Reconcile PRD with shipped storage shape

**Severity:** Low (docs — public release contract is internally inconsistent)

**Why:** `docs/prd/02-laravel-mfa.md:205-214` still requires "two migrations (one for factors,
one for attempts)" and a "customisable attempt model". `docs/ARCHITECTURE.md` decision D2
says 1.0 ships a single `mfa_factors` table with attempts embedded. PRD and architecture
disagree on the public contract.

**Files to touch:**

- `docs/prd/02-laravel-mfa.md` — update the "Publishable, customisable migrations" and
  "Customisable factor and attempt models" sections to reflect D2 (single table, no separate
  attempts model). Reference D2 directly.

**Exit criteria:** PRD, `docs/ARCHITECTURE.md`, README, changelog all tell the same storage
story.

---

## B-51 — Stop overstating the suppression count

**Severity:** Low (documentation accuracy)

**Why:** Recently-deleted `BACKLOG.md` claimed "Zero `@SuppressWarnings` annotations anywhere
in the codebase". That was wrong: `tests/Unit/Traits/ActsAsFactorTest.php:22` carries
`@SuppressWarnings("php:S1448")` and `tests/Unit/Middleware/SkipMfaTest.php:41` has an inline
`@SuppressWarnings("php:S3415")`. Multiple `@phpstan-ignore` annotations also exist
(`RequireMfaTest.php:60,122,184`, `FactorTest.php:66`, `ActsAsFactorTest.php:602`,
`FakeMfaManager.php:22`). The deletion of `BACKLOG.md` removed the false claim, but the
suppressions themselves remain.

Each suppression deserves a re-evaluation: is it justified by a contract surface (in which
case keep it with a clear comment), or is it papering over an under-tested branch (in which
case fix the underlying issue)?

**Files to touch:**

- `tests/Unit/Traits/ActsAsFactorTest.php:22` — the `S1448` suppression on the test class
  itself. Either split the test or document why the surface is intrinsically large.
- `tests/Unit/Middleware/SkipMfaTest.php:41` — `S3415` is "test of `assert(true)`-style
  assertion". Audit and either tighten the assertion or document why it's the right shape.
- `tests/Unit/Middleware/RequireMfaTest.php` (3 sites) and `tests/Unit/Models/FactorTest.php`,
  `tests/Unit/Traits/ActsAsFactorTest.php`, `tests/Fixtures/FakeMfaManager.php` — audit each
  `@phpstan-ignore`. Justify or remove.

**Exit criteria:** every remaining suppression carries a one-line comment explaining the
contract reason; `composer check` clean; `composer test` green.

---

## Out of scope (delivered by `sinemacula/laravel-iam`)

`DeviceMfaVerificationStore` — `MfaVerificationStore` implementation that reads / writes the
`last_mfa_verified_at` column on the `Device` record from `sinemacula/laravel-authentication`.
Not this repo's work; tracked in the IAM glue's own backlog. The `MfaVerificationStore`
contract here already exposes the optional `?CarbonInterface $at` argument that
implementation needs.
