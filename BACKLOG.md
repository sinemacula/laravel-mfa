# Backlog

Forward-looking work for `sinemacula/laravel-mfa`. Everything shipped in the 1.0 cycle has been
cleared from this file — the git log carries the per-commit audit trail. Only the durable
architectural context and the one explicitly-out-of-repo item remain.

The 1.0 candidate sits on `feature/release-1.0-prep`.

---

## Status

- **336 tests / 894 assertions** passing across Unit / Feature / Integration / Performance suites.
- **100% line / method / class coverage** on `src/` (531/531 statements, 132/132 methods, 26/26
  classes).
- **Mutation gate green** — 100% Mutation Code Coverage, **92% Covered MSI** on scoped paths
  (gate: 85%).
- **PHPBench benchmarks** covering every hot-path (TOTP, OTP, backup codes, FactorSummary).
- **`composer check -- --all --no-cache`** exits 0 across the whole repo. No `[[triage]]` rule
  suppressions in `.qlty/qlty.toml`. Zero `@SuppressWarnings` annotations anywhere in the
  codebase.

---

## Architecture reference

The package is designed to operate cleanly in three modes. Any new work must keep all three
working.

### Standalone

- Identity model implements `MultiFactorAuthenticatable`.
- Default `SessionMfaVerificationStore` keeps verification state in the session (per-device by
  construction).
- Works behind SessionGuard, Sanctum, Passport, or any custom guard whose `Auth::user()` returns
  a `MultiFactorAuthenticatable`. Sanctum integration is asserted by
  `tests/Integration/MultiAuthStackTest::testSanctumGuardSeesIdentityAndFactors`.

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

Historical record of the architectural calls. Anything new should be consistent with these
unless explicitly discussed.

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
- **D5 — Built-in driver factories live in the service provider.** The four shipped drivers
  (TOTP, email, SMS, backup codes) are registered against the manager via the standard
  `Mfa::extend(...)` API from `MfaServiceProvider::registerBuiltInDrivers()`. Built-in drivers
  are indistinguishable from consumer-registered ones, which is what the three-mode story needs.
  Consumer overrides via `Mfa::extend()` work because Laravel's `Manager` resolves the most-
  recent registration. Pinned by
  `tests/Integration/CustomDriverExtensionTest::testConsumerCanOverrideBuiltInTotpDriver`.
- **D6 — Lifecycle events are dispatched by the manager, not by consumer code.** Factor
  enrolment goes through `Mfa::enrol(Factor)`; factor removal goes through `Mfa::disable(Factor)`.
  Both invalidate the identity's setup-state cache and dispatch
  `MfaFactorEnrolled` / `MfaFactorDisabled` so audit subscribers do not have to rely on consumer
  cooperation. Five lifecycle events in total: `MfaChallengeIssued`, `MfaVerified`,
  `MfaVerificationFailed`, `MfaFactorEnrolled`, `MfaFactorDisabled`.
- **D7 — Both `Factor::$secret` and `Factor::$code` are encrypted at rest.** The `secret`
  column carries long-lived material (TOTP keys, hashed backup codes); the `code` column holds
  live OTPs during their expiry window. Encrypting both closes the read-only-DB-replay attack
  surface. Migration uses `text` for both so the encrypted ciphertext fits regardless of the
  configured OTP alphabet / length.
- **D8 — Test fixtures extend abstract stubs, not raw contracts.** `AbstractFactorStub` and
  `AbstractEloquentFactorStub` (in `tests/Fixtures/`) provide safe-default implementations of
  every `Factor` / `EloquentFactor` method. Anonymous test fixtures extend the relevant abstract
  and override only the methods they need — keeping every fixture well below the
  max-methods-per-class threshold without resorting to `@SuppressWarnings` annotations.

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
