# Verification Lifecycle and Events

## Purpose

This note records the event contract dispatched by `MfaManager`. That contract matters because audit-log sinks, SIEM
integrations, and consumer listeners attach to these events and expect the same ordering and payload on every release.

The shipped lifecycle surface is five events, all under `SineMacula\Laravel\Mfa\Events`: `MfaChallengeIssued`,
`MfaVerified`, `MfaVerificationFailed`, `MfaFactorEnrolled`, `MfaFactorDisabled`.

## Invariants

- Events are dispatched by `MfaManager`, never by driver implementations. Drivers receive `issueChallenge()` and
  `verify()` calls; the manager wraps each call with the corresponding event emission. Consumers who register custom
  drivers via `Mfa::extend(...)` automatically participate in the same event contract.
- `MfaChallengeIssued` fires after the driver's `issueChallenge()` returns without throwing. For OTP drivers the
  code has already been minted, persisted, and handed to the transport; for TOTP and backup codes the driver is a
  no-op and the event is purely a lifecycle signal.
- On successful verification, `MfaVerified` fires after the verification-store write. A listener that reads
  `Mfa::hasExpired()` inside `MfaVerified` observes the fresh timestamp — there is no "event fires, state catches up"
  window.
- `MfaVerificationFailed` always carries a `MfaVerificationFailureReason`. The enum is narrowed to the cases the
  manager actually emits: `FACTOR_LOCKED`, `CODE_INVALID`, `CODE_EXPIRED`, `CODE_MISSING`, `SECRET_MISSING`.
- `MfaFactorEnrolled` fires after the factor row has been persisted (`EloquentFactor::persist()` for Eloquent
  factors). Non-Eloquent factors still dispatch the event; the consumer owns their storage.
- `MfaFactorDisabled` fires after the row has been deleted for Eloquent factors. Non-Eloquent factors still dispatch
  the event and the consumer owns the discard.
- Enrolment and disable both invalidate the identity's setup-state cache before dispatching their event, so a listener
  that reads `Mfa::isSetup()` inside the handler observes the post-change state.
- Ownership is enforced before any lifecycle event fires. A factor belonging to a different identity raises
  `FactorOwnershipMismatchException` from `challenge()`, `verify()`, `enrol()`, and `disable()`; no event is
  dispatched on the mismatch path.
- `challenge()`, `enrol()`, `disable()`, and `issueBackupCodes()` are no-ops when no MFA-capable identity resolves.
  They dispatch nothing in that branch — consumers can call them unconditionally in bootstrap code.

## Success Path

- `challenge()` resolves the identity, asserts factor ownership, calls `FactorDriver::issueChallenge($factor)`, then
  dispatches `MfaChallengeIssued($identity, $factor, $driver)`.
- `verify()` resolves the identity, asserts ownership, rejects if `$factor->isLocked()` with a `FACTOR_LOCKED`
  failure, calls `FactorDriver::verify($factor, $code)`, persists the success/failure side effects on the factor row,
  writes through `MfaVerificationStore::markVerified()` on success, then dispatches either `MfaVerified` or
  `MfaVerificationFailed` last.
- `enrol()` resolves the identity, stamps ownership onto brand-new Eloquent rows (or asserts ownership on pre-existing
  rows), persists, invalidates the setup cache, then dispatches `MfaFactorEnrolled($identity, $factor, $driver)`.
- `disable()` resolves the identity, asserts ownership, deletes the row for Eloquent factors, invalidates the setup
  cache, then dispatches `MfaFactorDisabled($identity, $factor, $driver)`.
- `issueBackupCodes()` rotates the identity's `backup_code` batch atomically on the factor model's own connection and
  dispatches one `MfaFactorEnrolled` per freshly-minted code.

## Failure / Edge Cases

- `verify()` on a locked factor emits `MfaVerificationFailed` with `FACTOR_LOCKED` and returns `false` without
  calling the driver. The attempt counter is not incremented because the attempt never reached the driver.
- On driver-level verification failure, the manager classifies the reason from the factor's post-verify state using the
  priority order `SECRET_MISSING > CODE_EXPIRED > CODE_MISSING > CODE_INVALID`. `CODE_INVALID` is the default —
  `CODE_MISSING` only fires when a pending code exists but has no expiry stamp (a driver-persistence bug, not a user
  error).
- Unsupported identities short-circuit to `false` without dispatching `MfaVerificationFailed`. Unresolved drivers
  throw from `resolveDriver()` before any event is dispatched. Those branches are deliberately outside the event
  taxonomy — the enum does not advertise a case for them.
- Non-Eloquent factors participate in the lifecycle events but carry no row to mutate. `applyVerificationOutcome()`
  is skipped for them; attempt counters and lockouts only exist on factors whose implementation persists them.
- Backup-code rotation inside `issueBackupCodes()` opens its transaction on the factor model's connection, not the
  container-default connection, so the "atomic replace + N events" guarantee holds even when the consumer rebinds
  `config('mfa.factor.model')` to a model on a secondary database.

## Implementation Anchors

- `src/MfaManager.php`: `challenge()`, `verify()`, `enrol()`, `disable()`, `issueBackupCodes()`,
  `applyVerificationOutcome()`, `finaliseVerification()`, `rotateBackupCodeBatch()`, `resolveDriver()`,
  `assertFactorOwnership()`, `clearCache()`.
- `src/Events/MfaChallengeIssued.php`, `src/Events/MfaVerified.php`, `src/Events/MfaVerificationFailed.php`,
  `src/Events/MfaFactorEnrolled.php`, `src/Events/MfaFactorDisabled.php`.
- `src/Enums/MfaVerificationFailureReason.php`: the narrowed failure taxonomy.
- `src/Contracts/FactorDriver.php`: the driver-side `issueChallenge()` / `verify()` contract the manager wraps.
- `src/Exceptions/FactorOwnershipMismatchException.php`: the pre-event rejection path.

## Authoritative Tests

- `tests/Unit/MfaManagerChallengeTest.php`
  `testChallengeDispatchesToDriverAndPersistsEloquentFactor`
- `tests/Unit/MfaManagerChallengeTest.php`
  `testChallengeIsNoopWhenNoIdentity`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyReturnsFalseAndDispatchesWhenFactorLocked`
- `tests/Unit/MfaManagerVerifyTest.php`
  `testVerifyFailurePersistsAttemptAndDispatchesFailure`
- `tests/Unit/MfaManagerVerifySuccessTest.php`
  `testVerifySuccessDispatchesVerifiedEvent`
- `tests/Unit/MfaManagerVerifySuccessTest.php`
  `testVerifySuccessDoesNotDispatchFailureEvent`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testEnrolDispatchesEnrolledEvent`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testEnrolInvalidatesIsSetupCache`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testDisableDispatchesDisabledEvent`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testDisableInvalidatesIsSetupCache`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsSecretMissingForTotpShapedFactorWithoutSecret`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsCodeExpiredWhenPendingCodeHasExpired`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsCodeMissingWhenPendingCodeHasNoExpiry`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsCodeInvalidForTotpSecretMismatch`

## Change Triggers

Update this note when any of the following change:

- the set of five events or the payload shape of any of them
- the rule that the manager dispatches events and drivers do not
- the ordering rule that `MfaVerified` fires after the verification-store write
- the failure-reason taxonomy on `MfaVerificationFailureReason` or the priority order used to classify a driver
  failure
- whether enrolment and disable still invalidate the setup cache before dispatching
- whether ownership mismatches continue to fail before any event is emitted
- whether backup-code rotation continues to emit one `MfaFactorEnrolled` per code
