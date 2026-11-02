# Verification Lifecycle and Events

## Purpose

This note records how a verification runs: what is captured, what is checked under the lock, the one place a success
leaves the package, and the order of the events listeners and audit sinks attach to. The guide is
[Verification](../guides/verification.md).

## Invariants

- `Mfa::verify()` is the one way a code, a recovery code or an assertion becomes a proof. `Mfa::sendCode()` and
  `Mfa::requestAssertion()` are bound the same way, and `Mfa::offeredFactors()` is advisory.
- One binding (owner, application, sign-in, purpose) is captured by `Context\CallerContextResolver::binding()` and
  threaded through a code's issue, its check, the attempt's application, the driver and the proof. A sign-in id is never
  the Laravel session's id, so a code of sign-in A is looked up under B's session hash, finds nothing and answers
  `not_found`. This does not rely on forgetting codes at sign-in or sign-out, which a custom guard bypasses.
- With no binding, or no caller, nothing is sent, counted or reported.
- Under the identity's lock the caller and the binding are resolved again and compared by array form
  (`CallerContextResolver::still()`). A difference is `Exceptions\SignInChangedException`, thrown inside the
  transaction, answered `not_found` with no event and no count. A credential a bound `PendingSessionResolver` cannot
  validate there throws, uncaught.
- `Verification\PurposeRule` decides the purpose before anything is checked: a pending session is always `sign_in`; an
  active one is `step_up` or, when asked for, `sign_in`. `enrollment` and `reauthenticate` are refused. Routing to the
  seam is by pending or active, never by purpose.
- Each route counts exactly once: `Attempts\AttemptService::attempt()` for a code for a factor, a passkey's assertion
  and a recovery code, `Attempts\ChallengeCounters::report()` inside the gateway for a challenge.
- `AttemptService::throttled()` is the one reservation of the address's window, taken outside any transaction the
  package opens: passes and refusals give it back, counted failures keep it, and anything thrown gives it back.
- The seam is the last write in the transaction, so only the outer commit can fail after it. A thrown
  `OperationRefusedException` rolls back the count, the code's use, the TOTP step and the recovery code's use, and is
  answered as a failed result. Any other throwable propagates.
- The new proof's own acceptance is checked on its own (`check(Requirement::none(), $firstFactor, $proof)->accepted`),
  since an aggregate answer can come from an older proof. The result's evaluation then covers the whole requirement, and
  falling short of it is still a successful verification handed to the seam.
- Proofs are honest: `ObservedProperties::none()` for TOTP, SMS and email, and what its assertion observed for a
  passkey.
- Every event reporting a write goes through `Events\EventDispatcher`, once the change commits.
- `VerificationResult` and `Submission` keep secrets out of every route: `__debugInfo()` and `jsonSerialize()` leave out
  the completion, the channel's destination, the code and the response, and `__serialize()` throws.

## Success Path

```text
Mfa::verify(Submission, ?Purpose)
  1  caller = CallerContextResolver::resolve(VERIFY)             null -> failed not_found, no event, no count
  2  purpose = PurposeRule::resolve()                            refused -> failed not_accepted, one event, no count
  3  binding = CallerContextResolver::binding(caller, purpose)   null -> failed not_found, no event, no count
  4  factor = OperationGuard::factor(identity, id, application)  refusal -> failed, one event, no count
  5  AttemptService::throttled(ip, function () {
  6    FactorStateTransaction::forIdentity(identity, model, function () {   <- the identity lock
  7      CallerContextResolver::still(VERIFY, binding)           differs -> uncounted refusal, no event
  8      admission under the lock                                refusal -> one event, no count
  9      route: check the code and count it, exactly once        failed -> return, so the count commits
 10      generation = VerificationGeneration::current(identity); proof = new Proof(..., binding, generation)
 11      check(none, firstFactor, proof)->accepted false         -> throw, rolled back, not_accepted
 12      evaluation = check(whole requirement, all proofs including this one)
 13      result = VerificationResult::verified(proof, evaluation, amr, type)
 14      completion = PendingCompletion::complete(pending, result) or StepUp::stepUp(result)   <- last write
 15      queue VerificationPassed, then RecoveryCodeUsed and RecoveryCodesLow
 16    })
 17  })
 18  OperationRefusedException -> failed result, one event
```

`Mfa::sendCode()` takes the same shape: step 8 is the same admission, step 9 is `ChallengeGateway::send()`, and
`CodeSent` is queued when a code was sent, whichever gateway sent it. A send reports nothing else, since no attempt was
made.

On success, the listeners run once the transaction commits, in this order: the default seams' proof reaches the store,
`VerificationPassed`, `RecoveryCodeUsed`, `RecoveryCodesLow`. So a listener reading `Mfa::proofs()` sees the new proof.

## Failure / Edge Cases

- Every reason, its event and whether it counts are in [the guide](../guides/verification.md#failure-reasons). A factor
  at the failure ceiling, and an identity there on a recovery code, are `locked` with no time:
  `VerificationResult::failed()` lets `locked` lack one, and no other reason may carry one, as `Lockout::isDisabled()`,
  `ChallengeAdmission::locked()` and `Redemption::refused()` have it.
- `CodeCheck::MISSING` is an absent or foreign challenge, `not_found`, and `CodeCheck::SPENT` a used challenge with
  another code, `expired`; matching a used code is `replayed`. All three are counted through `report()`.
- A driver returns `CodeCheck`, so a matched step refused by `storeAcceptedStep()` is `replayed` and a code that matches
  no step of the window `invalid_code`.
- A passkey's gateway returns a `FailureReason` for an assertion that does not verify, each a counted failure, or throws
  an `OperationRefusedException` when it cannot verify at all, which counts nothing.
- A factor removed between the first look and the lock is `not_found`, reported with no factor or type, exactly as one
  that never existed.
- A pending session's further proofs are validated by `PendingContext` (bound to its identity, application and session,
  no first factor among them), and those of another generation, or dated in the future, are dropped before evaluating.
- A recovery code with no known first factor is refused before any hash is checked.
- A store that refuses the proof at the commit throws `ProofRefusedException` from `verify()`, with the code spent. A
  listener that throws keeps `Events\EventDispatcher`'s behaviour: its exception reaches the caller, and the change has
  committed. The address's slot is then given back, since the exception reaches the throttle.
- `SessionProofStore` reads a per-request snapshot, so the lock cannot show another request's writes, and no session
  locking is added. An application serialises overlapping requests on one Laravel session with `Route::block()`. What
  holds without it: A's code is refused in any request that read B, and a proof bound to A cannot be recorded on B.
- Once per attempt means one dispatch in this execution; durable delivery is out of scope.

## Implementation Anchors

- `src/Verification/VerificationService.php`, `SubmissionRoutes.php`, `ChallengeRequests.php`, `FactorOffers.php`,
  `PurposeRule.php`, `CheckOutcome.php`, `Submission.php`, `VerificationResult.php`.
- `src/Context/CallerContextResolver.php`: `binding()`, `still()`. `src/Context/SessionFirstFactor.php`.
- `src/Attempts/AttemptService.php`: `throttled()`, `attempt()`. `src/Attempts/ChallengeCounters.php`: `isUsable()`,
  `underLock()`, `report()`. `src/Attempts/ChallengeOutcome.php`.
- `src/Codes/PackageChallengeGateway.php`, `src/Passkeys/PasskeyAssertions.php`,
  `src/RecoveryCodes/RecoveryCodeService.php`: `admission()`, `redeem()`, `reportRedeemed()`.
- `src/Proofs/ProofStoreCompletion.php`: the default `PendingCompletion` and `StepUp`.
- `src/Exceptions/SignInChangedException.php`, `src/Exceptions/OperationRefusedException.php`.

## Authoritative Tests

- `tests/Feature/Verification/SignInBindingVerificationServiceTest.php`
- `tests/Feature/Verification/FailureReasonsVerificationServiceTest.php`
- `tests/Feature/Verification/CompletionVerificationServiceTest.php`
- `tests/Feature/Verification/CountingVerificationServiceTest.php`
- `tests/Feature/Verification/EventSequenceVerificationServiceTest.php`
- `tests/Feature/Verification/FactorOffersTest.php`
- `tests/Unit/Proofs/ProofStoreCompletionTest.php`

## Change Triggers

- A step of the flow moving, or the seam no longer being the last write.
- A failure reason, its event or whether it counts changing.
- What a binding holds, or where the sign-in id comes from.
- The order of the events.
