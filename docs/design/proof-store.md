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
  sign-in per store, keyed by its type (the morph class of an Eloquent identity, its class name otherwise) and its key
  as a string, so `User#7` and `Admin#7` never share one. A key that is neither a non-empty string nor an integer is
  refused with `UnsupportedIdentifierException` rather than collapsing identities onto one record.
- Beginning a sign-in forgets every proof of the identity's previous one, even under the same session id.
- A proof is recorded only for its identity's current sign-in: one bound to another session id, or to an identity with
  no sign-in, is refused with `ProofRefusedException`, never kept.
- A recorded proof counts only when it is bound to the identity, the application and the current sign-in it is read
  for, was made no later than now, and was made under the identity's current verification generation. Anything else,
  and a stored entry that cannot be read back as a proof, is left out. The proofs come back oldest first.
- The verification generation is `verification_generation` on the identity's row in the identity states table, 0 when
  it has none, read from the write connection. `Proofs\VerificationGeneration::advance()` creates the row when needed
  and moves the generation on by one inside a transaction on the storage connection; called inside the identity's
  factor state transaction it joins it and rolls back with it.
- The default store, `Proofs\SessionProofStore`, keeps each identity's sign-in and the full records of its proofs in
  the Laravel session under `mfa.proofs`. It keeps at most 50 proofs per sign-in, forgetting the earliest recorded but
  never a first factor. It is bound, not shared: every resolution reads the session of the request at hand.
- Laravel's `Login` event begins a sign-in, named by a fresh lowercase ULID, for an identity that can hold factors;
  `Logout` forgets it. A guard that fires neither calls `Proofs\GuardHooks::signedIn()` with the proof of the first
  factor it signed the identity in with, and `GuardHooks::signedOut()`. A guard that does neither leaves no sign-in, so
  nothing is recorded for it and nothing counts.
- A successful verification on a signed-in session records its proof through `Proofs\ProofService::record()`: an
  additional factor proof on the driver's channel, named by the factor's destination or the factor itself, or a
  recovery code proof for a backup code, bound to the application of the request (a bound `ApplicationResolver`'s
  answer, or the default guard's name), the current sign-in and the `step_up` purpose. A driver whose channel cannot
  carry a factor proves nothing.
- Disabling a factor forgets every proof made with it on the current session.
- `Mfa::proofs()` is the public read: the proofs of the current identity's sign-in on the current application that
  still count, or none without an MFA-capable identity or a sign-in.
- The `RequireMfa` middleware judges the newest additional factor or recovery code proof among them. None means
  `MfaRequiredException`; one older than the window, a window of zero or less, or one dated in the future means
  `MfaExpiredException`. The window is the route's `mfa:N` parameter, or `mfa.proofs.max_age_minutes`. A first factor
  alone is never a verification.

## Success Path

1. A person signs in through a session guard. `Login` fires and `BeginSignInOnLogin` begins a sign-in for them.
2. They verify a factor. `VerificationService::verify()` runs the driver, records the outcome on the factor, then
   `ProofService::record()` binds the proof to the current sign-in and generation and the store keeps it, before
   `MfaVerified` is dispatched.
3. A later request passes through `mfa` (or `mfa:5` for a step-up route). The middleware reads `Mfa::proofs()`, takes
   the newest verification and compares its age with the window.
4. They sign out. `Logout` fires and `ForgetSignInOnLogout` forgets the sign-in and its proofs.
5. When the identity's other sessions must verify again, as when a factor is removed or reset, the change advances
   the verification generation, and every session's proofs stop counting at their next read.

## Failure / Edge Cases

- Another identity signing in on a reused session inherits nothing: its own record is empty, and the previous
  identity's sign-in is forgotten when it signs out or signs in again.
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

## Implementation Anchors

- `src/Contracts/ProofStore.php`; `src/Exceptions/ProofRefusedException.php`.
- `src/Proofs/SessionProofStore.php`, `src/Proofs/ProofOwner.php`, `src/Proofs/VerificationGeneration.php`.
- `src/Proofs/GuardHooks.php`, `src/Proofs/BeginSignInOnLogin.php`, `src/Proofs/ForgetSignInOnLogout.php`.
- `src/Proofs/ProofService.php` (`proofs()`, `hasSignIn()`, `record()`, `forgetFactor()`, `application()`),
  `src/Proofs/ProofBindings.php`.
- `src/Verification/VerificationService.php` (`recordProof()`); `src/Lifecycle/LifecycleService.php` (`disable()`).
- `src/Http/Middleware/RequireMfa.php` (`lastVerifiedAt()`, `hasExpired()`, `parseMaxAgeMinutes()`),
  `src/Http/Middleware/SkipMfa.php`; `config/mfa.php` (`proofs.max_age_minutes`), `src/Proofs/ProofSettings.php`.

## Authoritative Tests

- `tests/Unit/Proofs/SessionProofStoreTest.php`: sign-ins, recording, every fail-closed read, the bound, malformed
  session data.
- `tests/Unit/Proofs/VerificationGenerationTest.php`, `tests/Unit/Proofs/ProofOwnerTest.php`.
- `tests/Unit/Proofs/GuardHooksTest.php`, `tests/Unit/Proofs/BeginSignInOnLoginTest.php`,
  `tests/Unit/Proofs/ForgetSignInOnLogoutTest.php`, `tests/Unit/Proofs/ProofBindingsTest.php`.
- `tests/Unit/Proofs/ProofServiceTest.php`; `tests/Unit/Verification/VerificationServiceTest.php` (the proof each
  verification records); `tests/Unit/Lifecycle/LifecycleServiceTest.php` (a disabled factor's proofs).
- `tests/Feature/Proofs/SignInProofsTest.php`: a reused session, sign-out, a guard calling neither hook, a custom
  guard's hooks, a generation bump across sessions.
- `tests/Unit/Http/Middleware/RequireMfaTest.php`, `tests/Feature/RequireMfaMiddlewareTest.php`,
  `tests/Feature/StepUpMaxAgeMiddlewareTest.php`: the window, the newest verification, the parameter.

## Change Triggers

- Changing the `ProofStore` contract, or what counts when proofs are read.
- Keying sign-ins other than by identity type and key, or letting a proof outlive its sign-in.
- Letting a guard that fires no event and calls no hook record a proof.
- Recording a proof outside a verification, or a proof whose channel cannot carry a factor.
- Judging the middleware on anything but the newest additional factor or recovery code proof.
