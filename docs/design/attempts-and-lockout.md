# Attempts and Lockout

## Purpose

This note records the per-factor rate-limiting contract. The shipped `Factor` model carries `attempts`,
`last_attempted_at`, and `locked_until` columns; the manager mutates them on every verification. The invariants below
are what downstream code (audit sinks, admin tooling, custom factor models) can rely on.

## Invariants

- Failed verifications increment `attempts` and stamp `last_attempted_at` to the attempt time. Success resets
  `attempts` to zero and clears `locked_until`.
- Lockout is per-factor, not per-identity. A locked TOTP factor does not prevent the user from verifying through a
  registered email or SMS factor.
- Lockout threshold is configured per-driver as `mfa.drivers.<driver>.max_attempts`. A threshold of zero (or any
  non-integer) means "no automatic lockout" — the counter still increments but the manager never calls
  `applyLockout()`.
- When a driver has a non-zero threshold and `attempts >= max_attempts` after the increment, the manager applies a
  lockout expiring `mfa.lockout_minutes` minutes in the future. The default fallback for that config key is 15.
- A locked factor short-circuits `verify()` before the driver is called. The attempt counter is NOT incremented on
  that branch — the attempt never reached the driver. A `MfaVerificationFailed` event still fires with reason
  `FACTOR_LOCKED`.
- A successful verification clears the lockout as a side effect of `resetAttempts()`. A stale `locked_until` in the
  future is not a permanent bar; a later legitimate success unblocks subsequent attempts.
- `isLocked()` is the live check: `locked_until !== null && locked_until->isFuture()`. A past `locked_until` is not
  a lockout — the manager does not eagerly clean stale stamps; it relies on the `isFuture()` comparison.
- Non-Eloquent factors have no row to mutate. The attempt / lockout state machine is only defined for implementations
  that persist it; the manager skips `applyVerificationOutcome()` for non-Eloquent factors entirely.

## Success Path

- `verify()` reads `$factor->isLocked()`. If the factor is locked, the manager dispatches a `FACTOR_LOCKED`
  failure and returns `false` without touching the counter or the driver.
- Otherwise the manager calls `FactorDriver::verify($factor, $code)`.
- On driver success, the manager calls `$factor->recordVerification()`. The trait stamps `verified_at`, calls
  `resetAttempts()` (zeroes `attempts`, nulls `locked_until`), and clears any pending code via `consumeCode()`,
  then `persist()` commits.
- On driver failure, the manager calls `$factor->recordAttempt()` (increments `attempts`, stamps
  `last_attempted_at`). If the post-increment count is at or above the configured per-driver threshold, it then calls
  `$factor->applyLockout(now()->addMinutes(mfa.lockout_minutes))`. Either way, `persist()` commits the mutation.
- OTP-issuing drivers (email, SMS) reset the attempt counter from inside `issueChallenge()` as part of minting a fresh
  code. That reset is paired with a fresh secret, so it cannot be used to wipe a lockout without rotating the live
  credential.

## Failure / Edge Cases

- `max_attempts = 0` disables automatic lockout for that driver. The counter still counts; admin tooling can inspect
  `attempts` for throttling heuristics.
- `max_attempts` resolved as a non-integer string coerces to `0`. That is deliberately failure-closed on the "no
  lockout" side rather than throwing, since a misconfigured string would otherwise take the enforcement path down on
  every request.
- `lockout_minutes` resolved as a non-integer falls back to the hardcoded default of 15. The consumer's bad config
  does not disable the lockout entirely.
- TOTP's `issueChallenge()` is a no-op — it does not reset attempts. A consumer cannot use "ask for a new TOTP
  challenge" to clear a lockout. Lockouts on TOTP are cleared only by a successful verification or by the lockout
  window expiring.
- Backup codes also have a no-op `issueChallenge()`. A consumer cannot use `challenge()` to reset the attempt counter
  on the backup-code driver either.
- Non-Eloquent factor implementations skip `applyVerificationOutcome()`, so they receive neither attempt-counter
  mutations nor lockouts from the manager. Those implementations must either supply their own state machine or accept
  that the shipped rate-limiting is not applied.
- A locked factor with a future `locked_until` returns `true` from `isLocked()` even while `attempts` is zero. The
  two columns are related but not equivalent; admin tooling that inspects lockout state should read `locked_until`,
  not the attempt count.

## Implementation Anchors

- `src/Traits/ActsAsFactor.php`: `recordAttempt()`, `resetAttempts()`, `applyLockout()`, `isLocked()`,
  `recordVerification()`, `consumeCode()`.
- `src/MfaManager.php`: lock-check short-circuit in `verify()`, `applyVerificationOutcome()` and its
  `resolveIntConfig()` calls for `mfa.drivers.<driver>.max_attempts` and `mfa.lockout_minutes`.
- `src/Drivers/EmailDriver.php`, `src/Drivers/SmsDriver.php` (and `src/Drivers/AbstractOtpDriver.php`):
  attempt-counter reset inside `issueChallenge()` paired with code rotation.
- `src/Models/Factor.php`: `attempts` / `locked_until` / `last_attempted_at` casts.
- `database/migrations/2026_04_15_000000_create_mfa_factors_table.php`: column definitions and defaults.

## Authoritative Tests

- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyReturnsFalseAndDispatchesWhenFactorLocked`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailurePersistsAttemptAndDispatchesFailure`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailureAppliesLockoutAtMaxAttemptsThreshold`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailureSkipsLockoutWhenMaxAttemptsIsZero`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailureUsesFallbackLockoutMinutesWhenConfigIsNonInt`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailureTreatsNonIntMaxAttemptsAsZero`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailureOnNonEloquentFactorSkipsStateMutation`
- `tests/Unit/MfaManagerVerifySuccessTest.php`
  `testVerifySuccessResetsAttemptCounter`

## Change Triggers

Update this note when any of the following change:

- the rule that a locked factor short-circuits `verify()` before the driver runs and without incrementing the counter
- the reset-on-success contract (`verified_at` stamped, `attempts` zeroed, `locked_until` nulled, pending code
  cleared)
- the `mfa.drivers.<driver>.max_attempts` / `mfa.lockout_minutes` config keys or their coercion behaviour
- the decision that OTP drivers reset attempts from inside `issueChallenge()` paired with a fresh code
- whether lockouts remain per-factor rather than per-identity
- whether `isLocked()` remains a live `isFuture()` check versus any eager cleanup of stale stamps
