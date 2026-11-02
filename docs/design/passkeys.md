# Passkeys

## Purpose

This note documents how a passkey becomes, stays and stops being a factor: the association record, the change gate
every registration, removal or change of a passkey passes through, and the assertions a passkey factor is verified
with. This package stores no WebAuthn credentials and runs no ceremonies of its own: those belong to the
authentication layer, reached through `Contracts\PasskeyGateway`.

## Invariants

- A passkey is a factor only through a record in `mfa_passkey_associations`. Its factor row holds the credential id in
  `credential_reference`; the two are written and deleted together, in one factor state transaction, and a factor whose
  association does not name the same owner and credential is unusable, as if it did not exist.
- A credential id is its canonical unpadded base64url form (`Passkeys\CredentialId`), compared exactly, case included;
  any other encoding of the same bytes is refused rather than normalised, so two spellings of one credential cannot pass
  as two. An association finds a credential by the SHA-256 hex digest of that string and compares the id itself in PHP,
  since a column's collation may ignore case.
- The credential id is the passkey factor's channel reference, so the combination policy's same-channel rule keeps the
  passkey that started the sign-in from being its second factor. A first factor that names no credential, such as a
  declared `passkey` first factor, accepts no passkey after it.
- `Passkeys\PasskeyChangeGate` runs inside its caller's transaction on the storage connection and refuses with a
  `LogicException` without one. It acts only for the request's validated caller (see
  `Context\CallerContextResolver`) on the application it names, under the identity's factor state lock, so its locks
  and its events wait for the caller's commit. A refusal is an `OperationRefusedException` carrying the reason.
- A registration is associated only when the application enables `passkey` and the identity is a person; otherwise the
  gate answers `null` and the credential stays a sign-in passkey only. Its binding must be the caller's own enrolment
  on its current sign-in (or its pending session), and the ceremony must have observed user presence: the
  registration's own evidence confirms the factor, so it is stored confirmed.
- Associating authorises an enrolment through `Enrollment\EnrollmentAuthority`: on an active session, a fresh step-up
  for `mfa.add_factor` when the identity has a confirmed factor, or the first factor proved again through the bound
  `Reauthenticator` (a first factor reauthentication of the current sign-in, under the current verification
  generation, made in the last five minutes) when it has none; on a pending session, only the bootstrap path (its
  credential allows `mfa.confirm_bootstrap_enrollment`, the application allows bootstrap for `passkey`, and the identity
  has no confirmed factor). Then the application's limits on confirmed factors enrolled through it apply, of the type
  and in all.
- A credential already associated, with this identity or another, is refused (`credential_associated`): a registration
  is never idempotent.
- With the identity's first additional factor, recovery codes are generated when the application accepts them and the
  session's first factor followed by the registration's own evidence meets the level the application issues them at.
- Removing an associated credential needs the bound `FreshnessGate` to find the session fresh for `mfa.remove_factor`
  and, while another confirmed factor remains, the operation's requirement met on the session's proofs without those
  made with the factor being removed. `Lifecycle\FactorRemoval` then asks the bound `LastFactorPolicy` again under the
  lock, deletes the factor and its association (and the recovery codes with the last confirmed factor), forgets the
  factor's proofs on the current session at once, revokes the identity's other sessions through the bound
  `SessionRevoker`, evaluates the current session's requirement again on the proofs it kept and hands a shortfall to
  the bound `SessionTransition`, and reports `FactorRemoved`.
- A change to what an associated credential proves (its id, key, owner or relying party) is refused outright: it is a
  removal and then a registration. Renaming it and its usage bookkeeping are not gated.
- `Passkeys\PasskeyAssertions` requests and verifies an assertion for one factor at a time, allowing exactly its
  associated credential, and only while the factor is a confirmed passkey of the caller's of an enabled type, not
  disabled, its association matches, the gateway still lists the credential, and the combination policy accepts it after
  the session's first factor. No ceremony starts with an empty or wider allowlist. Verifying is an attempt through
  `Attempts\AttemptService`, so a failed assertion counts against the factor and the identity; an assertion verified for
  another credential fails. A pending session needs `mfa.verify`.
- The legacy direct enrolment refuses a passkey: only the gate associates one.

## Success Path

- The authentication layer opens its transaction, stores the credential, and calls `registering()` with the canonical
  id, what the ceremony observed and its binding; the gate stores the confirmed factor and its association and returns
  the factor's summary with any recovery codes, which the caller reveals once it has committed. `PasskeyAssociated`,
  `FactorConfirmed` and, with codes, `RecoveryCodesGenerated` are dispatched on the commit.
- To remove a passkey, it calls `removing()` in the transaction that deletes the credential; the factor goes with it.
- To verify a passkey factor, the verification flow asks `PasskeyAssertions` for the options of a ceremony, hands the
  client's response back, and records the returned assertion's observed properties as the proof.

## Failure / Edge Cases

- A refused gate rolls back the caller's own write with everything the gate did; a caller that fails after an allowed
  gate rolls back the factor, the association, the recovery codes and the events with it.
- Removing a credential associated with nobody is a no-op; one associated with another identity is refused; an
  association whose factor is gone is deleted on its own.
- Two identities registering one credential at the same moment each hold only their own lock; the authentication
  layer's own uniqueness on credential ids is what keeps that from leaving two associations.
- The configuration check refuses an application that enables `passkey` while `Passkeys\UnavailablePasskeyGateway` is
  still bound; a gateway of the application's own that reports itself unavailable at run time is not refused, and lists
  nothing to offer.

## Seams Left

- Verification does not yet turn a verified assertion into a recorded proof; the verification flow will.
- The removal and recovery code flows of the package's own do not yet share `Lifecycle\FactorRemoval`; the lifecycle
  flow will.

## Implementation Anchors

- `src/Passkeys/PasskeyChangeGate.php`, `PasskeyAssertions.php`, `PasskeyAssociations.php`, `CredentialId.php`,
  `PasskeyRegistration.php`, `PasskeyAssociationResult.php`, `UnavailablePasskeyGateway.php`.
- `src/Drivers/PasskeyDriver.php`: states the channel, and refuses every code.
- `src/Enrollment/EnrollmentAuthority.php`, `src/Lifecycle/FactorRemoval.php`, `src/Lifecycle/RequiredFactorPolicy.php`.

## Authoritative Tests

- `tests/Feature/Passkeys/PasskeyChangeGateTest.php`: registrations, removals, changes and sequences in the caller's
  own transactions, refused and allowed.
- `tests/Unit/Passkeys/PasskeyAssertionsTest.php`, `tests/Unit/Passkeys/CredentialIdTest.php`.
- `tests/Unit/Enrollment/EnrollmentAuthorityTest.php`, `tests/Unit/Lifecycle/RequiredFactorPolicyTest.php`.
- `tests/Unit/Testing/Seams/PasskeyChangeGateContractTest.php`: the wiring kit an adapter proves itself with.

## Change Triggers

- A change to what associates a passkey, what refuses it, or what its removal does.
- A change to the credential id's form or how an association finds it.
