# Proof Store and Sign-Ins

## Purpose

This note records where a session's proofs are kept, how a sign-in begins and ends, what makes a recorded proof stop
counting, and how the `mfa` middleware reads the proofs to decide whether a request needs a fresh verification. The
proofs are the evidence every later answer (freshness, levels, requirements) is worked out from; nothing stores a single
"verified at" time in their place.

## Invariants

- Proofs live behind `Contracts\ProofStore`. The package never reads or writes a proof except through the bound store:
  `begin()`, `currentSession()`, `record()`, `proofs()`, `forgetFactor()` and `forget()`.
- A sign-in is named by the session id every proof made in it is bound to. Each identity has at most one current
  sign-in per application per store, keyed by its type (the morph class of an Eloquent identity, its class name
  otherwise), its key as a string and the application, so `User#7` and `Admin#7` never share one, and signing in to or
  out of one application leaves the identity's sign-in on another alone. A key that is neither a non-empty string nor
  an integer is refused with `UnsupportedIdentifierException` rather than collapsing identities onto one record.
- Beginning a sign-in forgets every proof of the identity's previous one on that application, even under the same
  session id.
- A proof is recorded only for its identity's current sign-in on its application: one bound to another session id, or
  to an identity with no sign-in there, is refused with `ProofRefusedException`, never kept.
- A recorded proof counts only when it is bound to the identity, the application and the current sign-in it is read
  for, was made no later than now, and was made under the identity's current verification generation. Anything else,
  and a stored entry that cannot be read back as a proof, is left out. The proofs come back oldest first.
- The verification generation is `verification_generation` on the identity's row in the identity states table, 0 when
  it has none, read from the write connection. `Proofs\VerificationGeneration::advance()` creates the row when needed
  and moves the generation on by one inside a transaction on the storage connection; called inside the identity's
  factor state transaction it joins it and rolls back with it.
- An enrolment's confirmation on a pending session is recorded as any further proof is, with purpose `enrollment`; on an
  active session it records nothing (see [Enrolment](enrollment.md)).
- The default store, `Proofs\SessionProofStore`, keeps each identity's sign-ins and the full records of their proofs
  in the Laravel session under `mfa.proofs`, by identity and then by application. It keeps at most 50 proofs per
  sign-in: past that, it forgets the earliest recorded other than the latest first factor, so the bound always holds
  and earlier first factors never crowd out an additional proof. It is bound, not shared: every resolution reads the
  session of the request at hand.
- Laravel's `Login` event begins a sign-in, named by a fresh lowercase ULID, for an identity that can hold factors, on
  the application the event's guard acts for (a bound `ApplicationResolver`'s answer for the request, or the guard's
  name); `Logout` and `CurrentDeviceLogout` forget it there. A guard that fires none of them calls
  `Proofs\GuardHooks::signedIn()` with the proof of the first factor it signed the identity in with, whose binding names
  the application, and `GuardHooks::signedOut()` with the application. A guard that does neither leaves no sign-in,
  so nothing is recorded for it and nothing counts, whatever sign-in the identity holds on another application.
- A successful verification's proof reaches the store through the seams its result is handed to: by default
  `Proofs\ProofStoreCompletion`, the `PendingCompletion` and `StepUp` of a package with no authentication layer. It
  refuses a failed result, and a binding whose owner, application or session is not the store's current sign-in, and for
  a pending session the pending context's as well, as `not_accepted`, so everything the verification did rolls back. It
  never begins a sign-in.
- The proof is an additional factor proof on the driver's channel, named by the factor's destination, credential or the
  factor itself, or a recovery code proof on no channel, bound to the one captured binding (see [Verification Lifecycle
  and Events](verification-lifecycle-and-events.md)), and stamped with the verification generation read under the
  identity's lock, after the code is checked.
- It is kept only once the storage connection's open transaction commits (`Database\AfterStorageCommit`, the rule events
  follow too), because a write to the Laravel session cannot roll back. A store that refuses it then throws
  `ProofRefusedException` from `verify()`, with the code spent. The success event waits with it and is dispatched after
  the proof has been kept.
- A sign-in id is fresh and never reused: the `Login` listener's is a ULID, and a caller of `GuardHooks` must see to its
  own. An application binding its own `PendingSessionResolver` alone begins the store's sign-in under the pending id
  through `GuardHooks::signedIn()`. Beginning a sign-in grants nothing by itself: the middleware or the pending context
  still decides. A guard that fires no event, calls no hook and stays in an existing sign-in stays in that sign-in.
- Disabling a factor forgets every proof made with it on the current session, on every application. It does not yet
  advance the verification generation: no shipped flow does, so the identity's other sessions keep counting a removed
  factor's proofs until the removal flow revokes them through the session revocation seam.
- `Mfa::proofs()` is the public read: the proofs of the current identity's sign-in on the current application that
  still count, or none without an MFA-capable identity or a sign-in.
- The `RequireMfa` middleware judges the newest additional factor or recovery code proof among them. None means
  `MfaRequiredException`; one older than the window, a window of zero or less, or one dated in the future means
  `MfaExpiredException`. The window is the route's `mfa:N` parameter, or `mfa.proofs.max_age_minutes`. A first factor
  alone is never a verification.

## Success Path

1. A person signs in through a session guard. `Login` fires and `BeginSignInOnLogin` begins a sign-in for them.
2. They verify a factor. `VerificationService::verify()` checks the code and counts the outcome under the identity's
   lock, makes the proof with the captured binding and the generation read there, and hands the result to `StepUp`; the
   store keeps the proof as the transaction commits, before `VerificationPassed` is dispatched.
3. A later request passes through `mfa` (or `mfa:5` for a step-up route). The middleware reads `Mfa::proofs()`, takes
   the newest verification and compares its age with the window.
4. They sign out. `Logout` (or `CurrentDeviceLogout`) fires and `ForgetSignInOnLogout` forgets the sign-in and its
   proofs on that guard's application.
5. When the identity's other sessions must verify again, the caller advances the verification generation with
   `VerificationGeneration::advance()`, and every session's proofs stop counting at their next read. No shipped flow
   advances it yet; removing and resetting factors will, through the session revocation seam.

## Failure / Edge Cases

- Another identity signing in on a reused session inherits nothing: its own record is empty, and the previous
  identity's sign-in is forgotten when it signs out or signs in again.
- Two guards over the same identity on one session (say `web` and `admin`) keep separate sign-ins: a `Login` or
  `Logout` on one leaves the other's sign-in and proofs alone, and a guard that fired no event cannot record against
  the other's sign-in.
- A guard that sets the user without firing `Login` (Laravel's `actingAs()`, `Auth::setUser()`, a custom guard that
  calls no hook) leaves no sign-in: verification still succeeds and updates the factor, but no proof is recorded and
  the middleware keeps requiring one.
- `GuardHooks::signedIn()` refuses a proof that is not a first factor, one bound to another identity, and one made under
  another generation than the identity's current one, as it would never count.
- A `Login` or `Logout` event for an identity that cannot hold factors, or whose key cannot name a record, changes
  nothing and never fails the sign-in or sign-out.
- A session holding something other than records under `mfa.proofs` reads as no sign-in.
- A non-numeric, negative or fractional `mfa:N` parameter raises `InvalidArgumentException` the first time the route
  handles a request.
- The session store reaches only its own session: `forgetFactor()` cannot reach the identity's other sessions, which
  stop counting a removed factor's proofs when the generation is advanced. A stateless guard rebinds `ProofStore`,
  keyed by an id that names one sign-in, not merely a device.
- Laravel writes the whole session back when a request ends, and does not serialise a session's requests unless a
  route asks it to (`Route::block()`). A request that loaded the session before a factor was removed on it can save
  its older copy afterwards, putting the forgotten proofs back. Forgetting a factor on the current session is
  therefore only as strong as the serialisation of its requests; advancing the generation is what holds whatever
  copy of the session is saved last.
- A store that refuses a proof throws `ProofRefusedException`. The verification it was part of is not yet one
  transaction, so the factor's changes and a consumed code stay committed; the default store never refuses a proof
  the service binds to its own current sign-in.

## Implementation Anchors

- `src/Contracts/ProofStore.php`; `src/Exceptions/ProofRefusedException.php`.
- `src/Proofs/SessionProofStore.php`, `src/Proofs/ProofOwner.php`, `src/Proofs/VerificationGeneration.php`.
- `src/Proofs/GuardHooks.php`, `src/Proofs/BeginSignInOnLogin.php`, `src/Proofs/ForgetSignInOnLogout.php`.
- `src/Proofs/ProofService.php` (`proofs()`, `beginSignIn()`, `endSignIn()`, `forgetFactor()`, `application()`,
  `applicationFor()`), `src/Proofs/ProofStoreCompletion.php`, `src/Proofs/ProofBindings.php`.
- `src/Verification/VerificationService.php` (`verify()`); `src/Lifecycle/FactorRemoval.php` (`erase()`).
- `src/Http/Middleware/RequireMfa.php` (`lastVerifiedAt()`, `hasExpired()`, `parseMaxAgeMinutes()`),
  `src/Http/Middleware/SkipMfa.php`; `config/mfa.php` (`proofs.max_age_minutes`), `src/Proofs/ProofSettings.php`.

## Authoritative Tests

- `tests/Unit/Proofs/SessionProofStoreTest.php`: sign-ins per application, recording, every fail-closed read, the
  bound, malformed session data.
- `tests/Unit/Proofs/VerificationGenerationTest.php`, `tests/Unit/Proofs/ProofOwnerTest.php`.
- `tests/Unit/Proofs/GuardHooksTest.php`, `tests/Unit/Proofs/BeginSignInOnLoginTest.php`,
  `tests/Unit/Proofs/ForgetSignInOnLogoutTest.php`, `tests/Unit/Proofs/ProofBindingsTest.php`.
- `tests/Unit/Proofs/ProofServiceTest.php`; `tests/Unit/Proofs/ProofStoreCompletionTest.php` and
  `tests/Feature/Verification/CompletionVerificationServiceTest.php` (the proof each verification hands over);
  `tests/Feature/Lifecycle/RemovingFactorTest.php` (a removed factor's proofs).
- `tests/Feature/Proofs/SignInProofsTest.php`: a reused session, sign-out and current-device sign-out, two guards on
  one session, a guard calling neither hook, a custom guard's hooks, a generation bump across sessions.
- `tests/Unit/Http/Middleware/RequireMfaTest.php`, `tests/Feature/RequireMfaMiddlewareTest.php`,
  `tests/Feature/StepUpMaxAgeMiddlewareTest.php`: the window, the newest verification, the parameter.

## Change Triggers

- Changing the `ProofStore` contract, or what counts when proofs are read.
- Keying sign-ins other than by identity type, key and application, or letting a proof outlive its sign-in.
- Advancing the verification generation from a shipped flow, such as factor removal.
- Letting a guard that fires no event and calls no hook record a proof.
- Recording a proof outside a verification, or a proof whose channel cannot carry a factor.
- Judging the middleware on anything but the newest additional factor or recovery code proof.
