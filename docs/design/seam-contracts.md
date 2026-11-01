# Seam Contracts

## Purpose

This note lists the contracts the package declares for the seams between it, an authentication layer and the
application: what each answers, and what a fail-closed answer is. They are declared together, ahead of the flows that
call them, so the flows can be built against one fixed set.

## Invariants

- Every seam is this package's own contract in `Contracts`, taking and returning this package's values (`Proof`,
  `ProofBinding`, `Requirement`, `Evaluation`, `VerificationResult`, `Channel`, `PendingContext`, `PasskeyAssertion`),
  never a class of another package. An adapter translates between the two.
- An answer that cannot be given safely is the refusing one: `null` for an unknown first factor, no reauthentication or
  no pending session, `false` for a passkey gateway that is unavailable or a factor that may not be removed, and "not
  fresh" for an operation with no setting or a session with no record.
- A call that changes state and answers nothing (`PendingCompletion`, `StepUp`, `SessionRevoker`, `SessionTransition`)
  reports a refusal or a failure by throwing, never by returning: a binding that does not validate, a proof that cannot
  be recorded, a session that cannot be ended or returned to pending. Returning means it was done, and a throw rolls
  back the factor state change the call runs in.
- Results cross the seams as structured values, never reduced to `amr`.
- A contract that no shipped flow calls yet has no default binding. The package resolves none of them until the flow
  that calls it is in place, with its default, except where noted below.
- `EventContextResolver` is the exception: the event dispatcher calls it, so it is bound by default to
  `Context\DefaultEventContextResolver`, which gives the identity, the application and the request (see
  [Event Catalogue](event-catalogue.md)).
- `CombinationPolicy` is the other exception: it is bound by default to `Assurance\DefaultCombinationPolicy` ahead of
  the requirement and verification flows that will call it, since they will use its default (see
  [Combination Policy](combination-policy.md)). No shipped flow calls it yet.

| Contract                 | Answers                                                                                       |
|--------------------------|-----------------------------------------------------------------------------------------------|
| `CombinationPolicy`      | Whether a factor may follow a first factor, and what a combination of proofs establishes      |
| `ProofStore`             | The proofs a session has made that still count; forgetting them by factor or for the session  |
| `RequirementPolicy`      | What a sign-in must prove after its first factor, composed from every source                  |
| `IdentityRequirement`    | What the identity itself requires                                                             |
| `TenantRequirement`      | What the active tenant requires                                                               |
| `RequirementCheck`       | Whether a session's proofs meet a requirement, judged on the newest proof meeting each part   |
| `FreshnessGate`          | Whether the session is fresh enough for a named operation                                     |
| `Reauthenticator`        | The proof of the first factor made again on an active session, or none                        |
| `PendingSessionResolver` | The request's pending session, as a `PendingContext`, or none                                 |
| `FirstFactorResolver`    | The proof of the first factor that started the session, or none when unknown or untrusted     |
| `PendingCompletion`      | Receives a successful verification on a pending session                                       |
| `StepUp`                 | Receives a successful verification on an active session                                       |
| `ChallengeGateway`       | Sends and checks a delivered factor's codes as bound challenges                               |
| `PasskeyGateway`         | Lists passkeys, and requests and verifies assertions limited to the associated credentials    |
| `SessionRevoker`         | Ends the identity's other sessions, or all of them, inside a factor change                    |
| `SessionTransition`      | Returns the current session to pending when a change leaves it short                          |
| `LastFactorPolicy`       | Whether the identity's last factor may be removed                                             |
| `SelfServiceRecovery`    | Whether an application offers its own recovery, and starting it                               |
| `SubjectTypeResolver`    | Whether an identity is a person                                                               |
| `ApplicationResolver`    | The application a request is for                                                              |
| `EventContextResolver`   | The scalar context every event carries                                                        |
| `SmsSender`              | Delivers an SMS message carrying a code                                                       |
| `EmailSender`            | Delivers an email message carrying a code                                                     |

- `Context\PendingContext` holds a pending session: the identity, the application, the session's public id, the first
  factor's proof, the outstanding requirement and the `PendingAction` cases the pending credential allows. It refuses a
  first factor's proof that is not a first factor or is bound to another identity, application or session, and actions
  that are not a list of pending actions each named once. A helper serves it only an action it `allows()`.
- `Passkeys\PasskeyAssertion` holds what a verified assertion observed: the credential and its `ObservedProperties`.

## Success Path

- An adapter, or the application, implements a contract and binds it in the container from a service provider; the
  flow that calls the contract resolves it when it runs, so a binding made after the package's provider applies.

## Failure / Edge Cases

- Resolving a contract that nothing has bound fails with Laravel's binding error; no shipped flow does so.
- A `PendingContext` that contradicts itself is refused with an `InvalidArgumentException` when it is built, so one
  that exists is consistent.

## Implementation Anchors

- `src/Contracts/`: one file per contract.
- `src/Context/PendingContext.php`, `src/Passkeys/PasskeyAssertion.php`.

## Authoritative Tests

- `tests/Unit/Context/PendingContextTest.php`
- `tests/Unit/Passkeys/PasskeyAssertionTest.php`

## Change Triggers

- A new seam, or a change to what a contract takes or answers.
- A flow starting to call a contract: its default and binding are added with it.
