# Enrolment

## Purpose

This note documents how a factor is enrolled: what authorises a start, how long the grant lives and why that is fixed
once, what the grant is bound to, what a confirmation checks again inside its transaction, and what a confirmation does
for the session. The API is in [Enrolment](../guides/enrollment.md).

## Invariants

- A factor is pending until a first valid code confirms it, and a pending factor is never usable or offered. A passkey
  is the one exception: its registration confirms it, through `Passkeys\PasskeyChangeGate`.
- What authorises a start is decided under the identity's factor state lock by
  `Enrollment\EnrollmentAuthority::authorize()`, which returns `Enrollment\GrantAuthority`: the kind
  (`Enums\EnrollmentAuthorization`) and the instant it ends. On an active session the bound `FactorChangeGate` decides
  it, asked for `mfa.add_factor` or, with no confirmed factor, `mfa.add_first_additional_factor`, and the grant ends
  when the gate says; the package refuses a grant it gives no end in the future. The default ends a step-up when
  `FreshnessGate::freshUntil(mfa.add_factor)` says, and a reauthentication five minutes after it was proved. The
  bootstrap path, which never asks the gate, ends when `PendingContext::$expiresAt` says.
- `expires_at` is the earlier of `now + mfa.enrollment.ttl_minutes` and that instant, floored to the second as it is
  stored, and a deadline past after flooring is `not_fresh`. It is written once, by the start, and never again. A grant
  is live only while `expires_at` is ahead and the verification generation it recorded is the identity's current one.
- No freshness is judged at confirmation: a later proof must not revive a grant that outlived the proof that authorised
  it. This is why the deadline is computed rather than probed: a probe (tightening maximum ages and searching) cannot
  see a rebound gate's own setting, and a stored proof fingerprint is more machinery than a timestamp.
- `Assurance\Evaluation::$metUntil` is how the default gate says it. `DefaultCombinationPolicy` computes it, for each
  part with a maximum age, as the latest evidence time among the combinations providing it plus that age, and takes the
  earliest across the parts. It is refused on an evaluation with an unmet part, and is in neither `toArray()` nor JSON.
  A rebound policy that reports none for a bounded requirement gives `null` from `freshUntil()`, so enrolment fails
  closed while `isFresh()` stays as it was for its other callers.
- `grant_hash` is the SHA-256 of an opaque 256-bit token returned once as a `RevealedSecret`; `session_id` is a keyed
  digest of the binding's sign-in (`Codes\CodeKeys::session()`), never Laravel's raw session id or the sign-in's. A row
  is looked up by hash, then its owner, application and session digest are compared exactly in PHP, because a database's
  collation may not be exact; every mismatch answers `not_found`. A `bootstrap` grant serves only a pending caller and
  the other two only an active one. The row is deleted at confirmation, so a repeat answers `not_found` and returns none
  of the secrets.
- Restarting discards any pending enrolment of the same identity, application and type, from any session, and expired
  ones of this application only; another application's belong to pruning. Delivered code rows of a discarded factor
  stay, and carry a keyed digest of the owner and the destination (`destination_hash`), which outlives the factor. The
  destination's cap counts by it, and a new enrolment challenge waits out `resend_cooldown_seconds` since the last
  enrolment code to it, so restarting and sending bypasses neither. A refused restart rolls back and leaves the
  enrolment under way. A new destination has its own count and cooldown, so a mistyped one can be corrected at once, and
  the identity's cap bounds that. An adapter's `ChallengeGateway` owns its own caps and sees a new factor id on a
  restart, so it must key them on what a restart keeps.
- Every write the flow needs fails closed. A model event that cancels the factor's save, the row's save or deletion, the
  count of an attempt or the record of a challenge throws `WriteCanceledException`, so the whole transaction rolls back
  and no confirmation, recovery code, event or usable grant comes of what was not stored.
- A row and a factor are matched to their owner exactly before anything acts on them. `FactorStateTransaction` hands
  over only the owner's own factors and `PendingEnrollments::ofApplication()` only its own rows, so on a
  case-insensitive collation a restart, a rename or a choice of preferred factor cannot reach another owner, and another
  owner's factor neither closes the bootstrap path nor counts towards a limit.
- A failure is reported with the factor as it was found. A refusal after a valid code rolls back a confirmation made on
  the same instance, so `VerificationFailed` carries a summary taken before it and never reads `confirmed`.
- A binding whose purpose is `enrollment` inverts the admission in `Attempts\ChallengeCounters`: only a pending factor
  holding a live enrolment bound to the binding and the caller, of an enabled type, with no question of the combination
  policy, refused while the identity's lockout is live. A confirmed factor under `enrollment`, and a pending factor
  under any other purpose, are refused, which is what makes an enrolment challenge never usable as an `mfa` one or the
  reverse. `report()` under `enrollment` changes no factor's or identity's count, and still refuses a binding naming
  another identity.
- `PackageChallengeGateway` maps the pending action by purpose: an enrolment send needs `mfa.start_bootstrap_enrollment`
  and an enrolment check `mfa.confirm_bootstrap_enrollment`, so `mfa.send_code` alone never reaches a pending factor.
- The enrolment's own cap (`mfa.enrollment.max_attempts`) counts only `invalid_code` and `replayed`, once each, under
  the lock. It does not infer the count from a challenge outcome's `counted`, as that also marks a missing or spent
  challenge. At the cap the factor and row are deleted, and that commits, because it returns. A factor's and an
  identity's failure counts are not charged.
- The lock order is unchanged: the identity's state, its factors, the enrolment row (read `FOR UPDATE` from the write
  connection once the identity's lock is held), then the owner's challenge.

## Success Path

- Start: resolve the caller for `mfa.start_bootstrap_enrollment`, and its binding with purpose `enrollment`; guard the
  identity; refuse a disabled type, a passkey and a channel that carries no factor; normalise the destination; take an
  IP address slot. Under the lock: resolve the caller again, read the identity's lockout, authorise, fix the expiry, ask
  the combination policy where it must be asked, discard what this replaces, count the pending limit, store the factor
  and its encrypted secret, write the row, send the first code inside the transaction, queue the events, and build the
  secrets last. They are returned only from a commit.
- Confirm: resolve the caller for `mfa.confirm_bootstrap_enrollment`, and take an IP address slot. Under the lock, in
  order: `still()` with the captured binding; the row re-read and compared; live expiry and generation (a dead grant
  discards the factor and commits); `OperationGuard::identity()`; the identity's lockout; the type enabled;
  `EnrollmentAuthority::reconfirm()`; the code along its route; then confirm the factor, delete the row, and complete.
- Complete on a pending session: `Verification\ProofAcceptance` refuses a proof not accepted after the first factor,
  evaluates the whole requirement with it, and hands it to `PendingCompletion` as the last write.
  `ProofStoreCompletion::complete()` takes purpose `enrollment` for an additional factor. An accepted proof may leave
  the session pending.
- Complete on an active session: nothing is recorded and `StepUp` is not called, because the authentication layer's
  step-up accepts only `step_up` and this code was bound to enrolling. The confirmation proof is evaluated only
  hypothetically, for recovery codes. `Requirements\SessionReevaluation`, shared with `Lifecycle\FactorRemoval`, then
  evaluates the requirement on the proofs the session holds and hands a shortfall to `SessionTransition`.
- `RecoveryCodes\RecoveryCodeIssuance::withFirstFactor()` issues a set when "first" holds under the lock, the
  application accepts them, and the known first factor followed by the actual confirmation proof reaches the
  application's level. It does not go through the freshness-gated `generate()`.
  `Requirements\ReenrollmentObligation::end()` runs in the same transaction, on this path and in the passkey gate.

## Failure / Edge Cases

- A wrong-code count and an abandonment commit, because they return. A valid code followed by a refusal throws, carried
  by `RefusedUnderLockException`, so the code's use, the TOTP step, the confirmation, the end of the obligation and the
  recovery codes all roll back. Returning a refusal alone would not roll any of it back.
- A sending cap throws `CodeNotSentException` out of the start's transaction, so nothing is left, with `retryAfter` kept
  for the answer. A code already sent cannot be recalled: a later failure of the transaction leaves a delivered code
  nothing can confirm, and nothing retries the transaction automatically.
- A `reauthentication` grant is refused once a confirmed factor exists, which is stricter than the bootstrap condition
  alone requires: that grant's authority was having no factor. So of two concurrent first confirmations, one succeeds
  and counts as first and the other is refused, on both paths.
- A combination refusal applies on an active session only to the identity's first additional factor while its first
  factor is known. Otherwise someone signed in by a phone code who enrols that same phone would be short and returned to
  pending, with nothing to offer.
- No pending-period identifier: a session keeps its id across a return to pending, and for an old bootstrap grant to be
  honoured in a later period the session must have activated with no confirmed factor and returned to pending within the
  grant's life, still with no factor, the same generation and the same first factor. Its authority is then unchanged,
  and the cap holds.
- A preferred flag is one per identity, cleared on its other factors across applications under the same lock, though a
  rename stays scoped to the enrolling application. Keeping preference on the identity state row was rejected: it adds a
  query per summary and a dependency a factor that is not Eloquent cannot meet.

## Implementation Anchors

- `src/Enrollment/EnrollmentService.php`, `EnrollmentStarter.php`, `EnrollmentConfirmer.php`, `PendingEnrollments.php`,
  `EnrollmentAuthority.php`, `GrantAuthority.php`, `EnrollmentGrant.php`, `EnrollmentRequest.php`,
  `EnrollmentStart.php`, `EnrollmentConfirmation.php`, `EnrollmentSettings.php`.
- `src/Enums/EnrollmentAuthorization.php`, `src/Models/Enrollment.php`, its migration.
- `src/Contracts/FreshnessGate.php` (`freshUntil()`), `src/Contracts/ProvisioningDriver.php`,
  `src/Contracts/CodeDeliveryDriver.php` (`normalizeDestination()`).
- `src/Assurance/Evaluation.php` (`$metUntil`), `src/Assurance/Combination.php` (`heldUntil()`),
  `src/Requirements/ConfiguredFreshnessGate.php`.
- `src/Verification/ProofAcceptance.php`, `src/Requirements/SessionReevaluation.php`,
  `src/RecoveryCodes/RecoveryCodeIssuance.php` (`withFirstFactor()`).
- `src/Attempts/ChallengeCounters.php` (`enrollingRefusal()`), `src/Codes/PackageChallengeGateway.php`.
- `src/Factors/FactorService.php` (`rename()`, `setPreferred()`), `src/Factors/FactorChange.php`,
  `src/Factors/FactorLabel.php`.

## Authoritative Tests

- `tests/Feature/Enrollment/GrantLifetimeEnrollmentStarterTest.php`
  `testAGrantThatOutlivedItsFreshnessStaysRefusedAfterANewerStepUp`, `testNothingMovesTheStoredExpiry`,
  `testAPolicyThatCannotSayRefusesTheEnrollment`, `testADeadlineIsFlooredToTheSecond`
- `tests/Feature/Enrollment/GrantBindingEnrollmentConfirmerTest.php`, `OwnerCollationEnrollmentStarterTest.php`,
  `CanceledWriteEnrollmentConfirmerTest.php`, `ProvisionedTypeEnrollmentStarterTest.php`
- `tests/Feature/Enrollment/GatesEnrollmentStarterTest.php`
- `tests/Feature/Enrollment/RechecksEnrollmentConfirmerTest.php`
- `tests/Feature/Enrollment/OutcomeEnrollmentConfirmerTest.php` `testACompletionsRefusalRollsEverythingBack`,
  `testAShortfallGoesToTheTransition`
- `tests/Feature/Enrollment/TotpEnrollmentStarterTest.php`, `DeliveredEnrollmentStarterTest.php`,
  `AttemptsEnrollmentConfirmerTest.php`, `ResendAndCancelEnrollmentServiceTest.php`,
  `EventSequenceEnrollmentServiceTest.php`
- `tests/Feature/Factors/RenameAndPreferredFactorServiceTest.php`
- `tests/Unit/Assurance/MetUntilEvaluationTest.php`
- `tests/Integration/Database/EnrollmentContentionTest.php`, `EnrollmentRaceTest.php`

## Change Triggers

- Any change to what authorises an enrolment, or to where a grant's expiry comes from.
- A new column on the enrolments table, or a change to what a row is compared against.
- A change to what a confirmation checks again, or to what is inside its transaction.
- A change to the admission or `report()` of a challenge whose purpose is `enrollment`.
