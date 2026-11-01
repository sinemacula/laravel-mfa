# Attempts and Lockout

## Purpose

This note records the per-factor rate-limiting contract. The shipped `Factor` model carries `attempts`,
`last_attempted_at`, and `locked_until` columns; the verification service mutates them on every verification. The
invariants below are what downstream code (audit sinks, admin tooling, custom factor models) can rely on.

## Invariants

- Failed verifications increment `attempts` and stamp `last_attempted_at` to the attempt time. Success resets
  `attempts` to zero and clears `locked_until`.
- Lockout is per-factor, not per-identity. A locked TOTP factor does not prevent the user from verifying through a
  registered email or SMS factor.
- The lockout threshold is `mfa.attempts.factor_limit` (default 5, from 1 to 20), the same for every driver: there is
  no setting that turns the lockout off.
- When `attempts >= factor_limit` after the increment, the verification service applies a lockout expiring
  `mfa.attempts.lockout_seconds` seconds in the future (default 900, from 60 to 86400).
- A locked factor short-circuits `verify()` before the driver is called. The attempt counter is NOT incremented on
  that branch — the attempt never reached the driver. A `MfaVerificationFailed` event still fires with reason
  `locked`.
- A successful verification clears the lockout as a side effect of `resetAttempts()`. A stale `locked_until` in the
  future is not a permanent bar; a later legitimate success unblocks subsequent attempts.
- `isLocked()` is the live check: `locked_until !== null && locked_until->isFuture()`. A past `locked_until` is not
  a lockout — the verification service does not eagerly clean stale stamps; it relies on the `isFuture()` comparison.
- Non-Eloquent factors have no row to mutate. The attempt / lockout state machine is only defined for implementations
  that persist it; the verification service skips `applyVerificationOutcome()` for non-Eloquent factors entirely.

## Success Path

- `verify()` reads `$factor->isLocked()`. If the factor is locked, the verification service dispatches a `locked`
  failure and returns `false` without touching the counter or the driver.
- Otherwise the verification service calls `FactorDriver::verify($factor, $code)`.
- On driver success, the verification service calls `$factor->recordVerification()`. The trait stamps `verified_at`
  and calls `resetAttempts()` (zeroes `attempts`, nulls `locked_until`), then `persist()` commits.
- On driver failure, the verification service calls `$factor->recordAttempt()` (increments `attempts`, stamps
  `last_attempted_at`). If the post-increment count is at or above `mfa.attempts.factor_limit`, it then calls
  `$factor->applyLockout(now()->addSeconds(mfa.attempts.lockout_seconds))`. Either way, `persist()` commits the
  mutation.
- Sending a delivered code (email, SMS) resets nothing: neither the factor's attempt counter nor its lockout, so asking
  for a new code never buys more guesses (see [Delivered Codes](delivered-codes.md)).

## Failure / Edge Cases

- A limit or lockout that is not an integer within its bounds fails closed with an `InvalidArgumentException` naming
  the key, rather than disabling or shortening the lockout. The package checks both when it boots (see the
  application configuration design note), so a malformed value stops the deployment rather than the first failed
  verification.
- TOTP's `issueChallenge()` is a no-op — it does not reset attempts. A consumer cannot use "ask for a new TOTP
  challenge" to clear a lockout. Lockouts on TOTP are cleared only by a successful verification or by the lockout
  window expiring.
- Backup codes also have a no-op `issueChallenge()`. A consumer cannot use `challenge()` to reset the attempt counter
  on the backup-code driver either.
- Non-Eloquent factor implementations skip `applyVerificationOutcome()`, so they receive neither attempt-counter
  mutations nor lockouts from the verification service. Those implementations must either supply their own state machine
  or accept that the shipped rate-limiting is not applied.
- A locked factor with a future `locked_until` returns `true` from `isLocked()` even while `attempts` is zero. The
  two columns are related but not equivalent; admin tooling that inspects lockout state should read `locked_until`,
  not the attempt count.

## Implementation Anchors

- `src/Concerns/ActsAsFactor.php`: `recordAttempt()`, `resetAttempts()`, `applyLockout()`, `isLocked()`,
  `recordVerification()`.
- `src/Verification/VerificationService.php`: lock-check short-circuit in `verify()`, `applyVerificationOutcome()`
  and its `Attempts\AttemptSettings` reads of `factorLimit()` and `lockoutSeconds()`.
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
  `testVerifyFailureRefusesAMalformedAttemptLimit`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailureOnNonEloquentFactorSkipsStateMutation`
- `tests/Unit/Verification/VerificationServiceTest.php`
  `testTheAttemptReachingTheLimitLocksTheFactor`
- `tests/Unit/Verification/VerificationServiceTest.php`
  `testAFailureBelowTheDefaultLimitDoesNotLock`
- `tests/Unit/Attempts/AttemptSettingsTest.php`
- `tests/Unit/MfaManagerVerifySuccessTest.php`
  `testVerifySuccessResetsAttemptCounter`
- `tests/Unit/Verification/VerificationServiceTest.php`
  `testSendingACodeResetsNothing`

## Change Triggers

Update this note when any of the following change:

- the rule that a locked factor short-circuits `verify()` before the driver runs and without incrementing the counter
- the reset-on-success contract (`verified_at` stamped, `attempts` zeroed, `locked_until` nulled)
- the `mfa.attempts.factor_limit` / `mfa.attempts.lockout_seconds` config keys or their bounds
- the rule that sending a delivered code resets no attempt counter and lifts no lockout
- whether lockouts remain per-factor rather than per-identity
- whether `isLocked()` remains a live `isFuture()` check versus any eager cleanup of stale stamps
