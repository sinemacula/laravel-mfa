# Verification Lifecycle and Events

## Purpose

This note records the event contract dispatched behind `MfaManager` by the package's capability services. That contract
matters because audit-log sinks, SIEM integrations, and consumer listeners attach to these events and expect the same
ordering and payload on every release.

The shipped lifecycle surface is five events, all under `SineMacula\Laravel\Mfa\Events`: `MfaChallengeIssued`,
`MfaVerified`, `MfaVerificationFailed`, `MfaFactorEnrolled`, `MfaFactorDisabled`. They are dispatched until the
enrolment, verification and lifecycle flows move to the catalogue described in [Event Catalogue](event-catalogue.md),
whose events carry summaries and a scalar context and are dispatched after the commit.

## Invariants

- Events are dispatched by the package's services (verification, enrolment, lifecycle, backup codes), never by driver
  implementations. Drivers receive `issueChallenge()` and `verify()` calls; the verification service wraps each call
  with the corresponding event emission. Consumers who register custom drivers via `Mfa::extend(...)` automatically
  participate in the same event contract.
- `MfaChallengeIssued` fires after the driver's `issueChallenge()` returns without throwing. For OTP drivers the
  code has already been minted, persisted, and handed to the transport; for TOTP and backup codes the driver is a
  no-op and the event is purely a lifecycle signal.
- On successful verification, `MfaVerified` fires after the proof is recorded on the identity's sign-in. A listener
  that reads `Mfa::proofs()` inside `MfaVerified` observes the new proof — there is no "event fires, state catches up"
  window.
- `MfaVerificationFailed` always carries a `FailureReason` and an internal `detail`. The verification service emits
  four of the reasons: `locked`, `invalid_code`, `expired` and `not_confirmed`. The detail tells apart failures that
  share a reason, such as an expired code and a code without an expiry, and is for listeners and logs only.
- `MfaFactorEnrolled` fires after the factor row has been persisted (`EloquentFactor::persist()` for Eloquent
  factors). Non-Eloquent factors still dispatch the event; the consumer owns their storage.
- `MfaFactorDisabled` fires after the row has been deleted for Eloquent factors. Non-Eloquent factors still dispatch
  the event and the consumer owns the discard.
- Enrolment and disable both finish their change before dispatching their event, and `Mfa::isSetup()` reads the
  factors on every call, so a listener that reads it inside the handler observes the post-change state.
- Ownership is enforced before any lifecycle event fires. A factor belonging to a different identity raises
  `FactorOwnershipMismatchException` from `challenge()`, `verify()`, `enroll()`, and `disable()`; no event is
  dispatched on the mismatch path.
- `challenge()`, `enroll()`, `disable()`, and `issueBackupCodes()` are no-ops when no MFA-capable identity resolves.
  They dispatch nothing in that branch — consumers can call them unconditionally in bootstrap code.

## Success Path

- `challenge()` resolves the identity, asserts factor ownership, calls `FactorDriver::issueChallenge($factor)`, then
  dispatches `MfaChallengeIssued($identity, $factor, $driver)`.
- `verify()` resolves the identity, asserts ownership, rejects if `$factor->isLocked()` with a `locked`
  failure, calls `FactorDriver::verify($factor, $code)`, persists the success/failure side effects on the factor row,
  records the proof through the bound `ProofStore` on success, then dispatches either `MfaVerified` or
  `MfaVerificationFailed` last.
- `enroll()` resolves the identity, stamps ownership onto brand-new Eloquent rows (or asserts ownership on pre-existing
  rows), persists, then dispatches `MfaFactorEnrolled($identity, $factor, $driver)`.
- `disable()` resolves the identity, asserts ownership, deletes the row for Eloquent factors, forgets the factor's
  proofs on the current session, then dispatches `MfaFactorDisabled($identity, $factor, $driver)`.
- `issueBackupCodes()` rotates the identity's `backup_code` batch atomically in the identity's factor state transaction
  and dispatches one `MfaFactorEnrolled` per freshly-minted code.

## Failure / Edge Cases

- `verify()` on a locked factor emits `MfaVerificationFailed` with `locked` and returns `false` without
  calling the driver. The attempt counter is not incremented because the attempt never reached the driver.
- On driver-level verification failure, the verification service classifies the reason from the factor's post-verify
  state in priority order: `not_confirmed` when there is neither a pending code nor a secret, `expired` when the code's
  expiry has passed, `expired` again when a pending code has no expiry stamp (a driver-persistence bug, not a user
  error, told apart by its detail), and `invalid_code` otherwise, the default.
- Unsupported identities short-circuit to `false` without dispatching `MfaVerificationFailed`. Unresolved drivers throw
  from `DriverResolver::resolve()` before any event is dispatched. Those branches are deliberately outside the event
  taxonomy.
- Non-Eloquent factors participate in the lifecycle events but carry no row to mutate. `applyVerificationOutcome()`
  is skipped for them; attempt counters and lockouts only exist on factors whose implementation persists them.
- Backup-code rotation inside `issueBackupCodes()` runs in the identity's factor state transaction on the storage
  connection, so the "atomic replace + N events" guarantee holds wherever `mfa.storage.connection` puts the tables, and
  a listener that throws rolls the whole rotation back.

## Implementation Anchors

- `src/Verification/VerificationService.php`: `challenge()`, `verify()`, `applyVerificationOutcome()`,
  `finalizeVerification()`.
- `src/Enrollment/EnrollmentService.php`: `enroll()`. `src/Lifecycle/LifecycleService.php`: `disable()`.
- `src/RecoveryCodes/RecoveryCodeService.php`: `issueBackupCodes()`, `rotateBackupCodeBatch()`.
- `src/Drivers/DriverResolver.php`: `resolve()`, `assertMatchesFactor()`. `src/Factors/FactorOwnership.php`:
  `assert()`.
- `src/Events/MfaChallengeIssued.php`, `src/Events/MfaVerified.php`, `src/Events/MfaVerificationFailed.php`,
  `src/Events/MfaFactorEnrolled.php`, `src/Events/MfaFactorDisabled.php`.
- `src/Enums/FailureReason.php`: the failure reasons, shared with the rest of the package.
- `src/Contracts/FactorDriver.php`: the driver-side `issueChallenge()` / `verify()` contract the verification service
  wraps.
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
  `testEnrollDispatchesEnrolledEvent`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testEnrollIsSeenByIsSetupAtOnce`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testDisableDispatchesDisabledEvent`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testDisableIsSeenByIsSetupAtOnce`
- `tests/Unit/MfaManagerLifecycleTest.php`
  `testDisableStopsTheFactorsProofsCounting`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsNotConfirmedForTotpShapedFactorWithoutSecret`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsExpiredWhenPendingCodeHasExpired`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsExpiredWhenPendingCodeHasNoExpiry`
- `tests/Unit/MfaManagerClassifyFailureTest.php`
  `testClassifyFailureReturnsInvalidCodeForTotpSecretMismatch`
- `tests/Unit/Verification/VerificationServiceTest.php`
  `testAFailureIsReportedWithItsReason`

## Change Triggers

Update this note when any of the following change:

- the set of five events or the payload shape of any of them
- the rule that the package's services dispatch events and drivers do not
- the ordering rule that `MfaVerified` fires after the proof is recorded
- the failure reasons the verification service emits, their details, or the priority order used to classify a driver
  failure
- whether enrolment and disable still finish their change before dispatching
- whether ownership mismatches continue to fail before any event is emitted
- whether backup-code rotation continues to emit one `MfaFactorEnrolled` per code
