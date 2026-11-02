# Seam Contracts

## Purpose

This note lists the contracts the package declares for the seams between it, an authentication layer and the
application: what each answers, what a fail-closed answer is, the default bound for each, what the authentication
layer provides for each, and the calls it makes back into this package. They are declared together, ahead of the flows
that call them, so the flows can be built against one fixed set.

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
- Every seam has a default that works without an authentication layer and fails closed, bound by the `*Bindings`
  class of the capability whose state it reads (or `Seams\SeamBindings` for one that reads nothing of the package), so
  a binding made after the package's provider replaces it. The exceptions are `PendingCompletion` and `StepUp`, whose
  defaults come with verification, and `SelfServiceRecovery`, whose default comes with the lifecycle flows; nothing
  resolves them yet. `ApplicationResolver` has no binding either: without one, the application is the guard's name.
- `EventContextResolver` is bound to `Context\DefaultEventContextResolver`, which gives the identity, the application
  and the request (see [Event Catalogue](event-catalogue.md)).
- `ProofStore` is bound to `Proofs\SessionProofStore`, which keeps each sign-in's proofs in the Laravel session (see
  [Proof Store and Sign-Ins](proof-store.md)).
- `CombinationPolicy` is bound to `Assurance\DefaultCombinationPolicy` (see
  [Combination Policy](combination-policy.md)); the default `RequirementCheck` calls it.
- The requirement seams are bound since `Mfa::requirement()`, `Mfa::isFresh()` and the `mfa` middleware call them:
  `RequirementPolicy` to `Requirements\ConfiguredRequirementPolicy`, `IdentityRequirement` to
  `Requirements\IdentityContractRequirement`, `TenantRequirement` to `Requirements\NoTenantRequirement`,
  `RequirementCheck` to `Requirements\ProofRequirementCheck` and `FreshnessGate` to
  `Requirements\ConfiguredFreshnessGate` (see [Requirements and Freshness](requirements-and-freshness.md)). A
  `FreshnessGate` bound in its place is handed this package's own setting for the operation as part of the caller's
  requirement, and must apply the stricter of that and its own.
- `PendingSessionResolver` is bound to `Context\NoPendingSessionResolver`: no request carries a pending session. A
  resolver answers `null` only for a request that carries no pending credential, and throws for one that does not
  validate.
- `SubjectTypeResolver` is bound to `Context\IdentityContractSubjectType`: a person is a `MultiFactorAuthenticatable`
  whose `canHoldFactors()` is true. The bound resolver is the authority: `Factors\OperationGuard`, the challenge
  counters and every helper ask it.
- `FirstFactorResolver` is bound to `Applications\DeclaredFirstFactorResolver`: the application's `first_factor`, for
  an identity with a sign-in on it, as a first factor naming no destination or credential, observing nothing, bound to
  the sign-in under the identity's current verification generation and dated at the Unix epoch. When it was made is not
  known, so it establishes the channel a further factor must be independent of and supplies no freshness of its own.
  The configuration check refuses an application with no declaration while this default is the one bound.
- `Reauthenticator` is bound to `Seams\RefusingReauthenticator`, which never proves the first factor again, so enrolling
  a first additional factor on an active session fails closed until the application binds one.
- `SessionRevoker` is bound to `Proofs\GenerationSessionRevoker`, which advances the identity's verification generation
  (see [Proof Store and Sign-Ins](proof-store.md)). Revoking the others reads the current sign-in and its counting
  proofs first, advances the generation inside the change, and once the change commits records those proofs again on
  the same sign-in under exactly the generation it advanced to, only while the store still names that sign-in and
  dropping a refusal. A later revocation in the same change therefore still wins, and a change that rolls back revokes
  nothing. The Laravel sessions themselves go on; the other sessions must verify again.
- `SessionTransition` is bound to `Http\MiddlewareSessionTransition`, which changes nothing: the requirement is worked
  out again on every request from the configuration, the identity contract and the identity's state row, so the `mfa`
  middleware gates a session left short until it meets it again, and the session keeps its proofs, as a pending session
  does.
- `ChallengeGateway` is bound to `Codes\PackageChallengeGateway`, the package's own delivered codes, owned exactly as an
  authentication layer must own its challenges (see the reverse calls below). It serves only a binding that is exactly
  the caller's own: its identity, its application and its session (the pending session's, or the current sign-in's).
  A request carrying a pending session never reaches an active sign-in of the same identity elsewhere.
- `PasskeyGateway` is bound to `Passkeys\UnavailablePasskeyGateway`: no passkey is registered, nothing verifies, and
  starting a ceremony is a `LogicException`. The configuration check refuses an application that enables `passkey`
  while it is bound (see [Passkeys](passkeys.md)).
- `LastFactorPolicy` is bound to `Lifecycle\RequiredFactorPolicy`: while the identity's own contract, or any configured
  application set to `always`, requires a factor, the last factor some configured application accepts (confirmed, of a
  type an application enables) may not be removed.
- Authentication's proof kinds are this package's four plus `external_reauthentication`, which this package does not
  add. An adapter maps them one way, by value, onto `ProofKind`:

  | Authentication's kind           | This package's proof                                                                 |
  |---------------------------------|--------------------------------------------------------------------------------------|
  | `first_factor`                  | `first_factor`                                                                       |
  | `first_factor_reauthentication` | `first_factor_reauthentication`                                                      |
  | `external_reauthentication`     | `first_factor_reauthentication` on an `external_provider` channel, observing nothing |
  | `additional_factor`             | `additional_factor`                                                                  |
  | `recovery_code`                 | `recovery_code`                                                                      |

  The mapped external reauthentication keeps its own time and binding, carries the `reauthenticate` purpose, and conveys
  no assurance: it asserts no observed property, so it meets no additional verification, multifactor, level or phishing
  resistance part, and only renews the time of a reauthentication with the first factor. This package never makes such
  a proof and never hands one back, so the mapping runs one way only. Trusting a provider's own evidence for more is a
  separate decision, made by rebinding the combination policy.

| Contract                 | Answers                                                                     | `laravel-authentication` provides                  |
|--------------------------|-----------------------------------------------------------------------------|----------------------------------------------------|
| `CombinationPolicy`      | Whether a factor may follow a first factor, and what proofs establish       | Nothing: this package's own                        |
| `ProofStore`             | The current sign-in and its proofs that still count; forgetting them        | The session's proof records                        |
| `RequirementPolicy`      | What a sign-in must prove after its first factor                            | Its additional-factor requirement, mapped          |
| `IdentityRequirement`    | What the identity itself requires                                           | Nothing: the identity contract                     |
| `TenantRequirement`      | What the active tenant requires                                             | Its tenant policy's requirement                    |
| `RequirementCheck`       | Whether a session's proofs meet a requirement                               | Nothing: it calls this package's check             |
| `FreshnessGate`          | Whether the session is fresh enough for a named operation                   | Its freshness policy                               |
| `Reauthenticator`        | The first factor proved again on an active session, or none                 | Its reauthentication with the first factor         |
| `PendingSessionResolver` | The request's pending session, as a `PendingContext`, or none               | Its validated pending credential                   |
| `FirstFactorResolver`    | The first factor's proof on the session, or none when unknown or untrusted  | The session's first-factor proof                   |
| `PendingCompletion`      | Receives a successful verification on a pending session                     | Satisfying the pending session                     |
| `StepUp`                 | Receives a successful verification on an active session                     | Its step-up                                        |
| `ChallengeGateway`       | Sends and checks a delivered factor's codes as bound challenges             | Its `mfa` challenges                               |
| `PasskeyGateway`         | Lists passkeys, and requests and verifies assertions for allowed ones       | Its WebAuthn credentials and ceremonies            |
| `SessionRevoker`         | Ends the identity's other sessions, or all of them, inside a factor change  | Logging out everywhere, optionally but the current |
| `SessionTransition`      | Returns the current session to pending when a change leaves it short        | Returning a session to pending                     |
| `LastFactorPolicy`       | Whether the identity's last factor may be removed                           | Nothing, or a tenant-aware policy of the iam layer |
| `SelfServiceRecovery`    | Whether an application offers its own recovery, and starting it             | Nothing: the application's own                     |
| `SubjectTypeResolver`    | Whether an identity is a person                                             | Its subject type                                   |
| `ApplicationResolver`    | The application a request is for                                            | The session's application                          |
| `EventContextResolver`   | The scalar context every event carries                                      | Its event context                                  |
| `SmsSender`              | Delivers an SMS message carrying a code                                     | The gateway its own codes are sent through         |
| `EmailSender`            | Delivers an email message carrying a code                                   | The gateway its own codes are sent through         |

The reverse calls are the critical enforcement points, made by the authentication layer into this package inside its
own transaction on the storage connection:

| Call                                                  | Made                                                                                  |
|-------------------------------------------------------|---------------------------------------------------------------------------------------|
| `Attempts\ChallengeCounters::isUsable()`              | Before sending or checking an `mfa` challenge: is the factor usable, is it locked     |
| `Attempts\ChallengeCounters::report()`                | With every outcome, in the transaction that consumes the challenge, never later       |
| `Passkeys\PasskeyChangeGate::registering()`           | Before storing a registered passkey: associates it as a factor where enabled          |
| `Passkeys\PasskeyChangeGate::removing()`              | Before deleting a passkey: removes its factor under the removal rules                 |
| `Passkeys\PasskeyChangeGate::changing()`              | Before changing what a passkey proves: refused for an associated one                  |

Both refuse with a `LogicException` outside a transaction, so their locks are held until the caller commits; the lock
order is the identity's state, then its factors, then the caller's own challenge or credential. A refusal is an
exception that rolls the caller's change back with it.

- `Context\PendingContext` holds a pending session: the identity, the application, the session's public id, the first
  factor's proof, the outstanding requirement and the `PendingAction` cases the pending credential allows. It refuses a
  first factor's proof that is not a first factor or is bound to another identity, application or session, and actions
  that are not a list of pending actions each named once. A helper serves it only an action it `allows()`.
- `Passkeys\PasskeyAssertion` holds what a verified assertion observed: the credential and its `ObservedProperties`.

## Success Path

- An adapter, or the application, implements a contract and binds it in the container from a service provider; the
  flow that calls the contract resolves it when it runs, so a binding made after the package's provider applies.
- `Context\CallerContextResolver` decides who every helper that returns summaries, sends a code or reveals a secret
  serves: a pending session only for the `PendingAction` the helper needs, as its own identity, and otherwise the
  guard's signed-in person; only a person either way. A helper that names no action (generating recovery codes, the
  direct enrolment, `disable()`, `isSetup()` and `proofs()`) serves active sessions only; `recoveryCodes()` needs
  `mfa.list_factors`, as `getFactors()` does.
- `Testing\Seams` holds a contract kit per seam: a trait of tests with abstract hooks, in `Testing\Seams\Concerns`,
  delegating each check to a `*Contract` class of static assertions. This package's tests use the traits to prove its
  defaults and call the assertions on deliberately faulty implementations to prove the kit rejects them; an adapter's
  test case uses the same traits. The kits live in `src/` because a dependent package does not load another's
  development autoloading; they need PHPUnit, as Laravel's own testing helpers do. They check safety guarantees, not
  capabilities a default lacks.

## Failure / Edge Cases

- Resolving `PendingCompletion`, `StepUp`, `SelfServiceRecovery` or `ApplicationResolver` with nothing bound fails with
  Laravel's binding error; no shipped flow does so.
- A pending credential that does not validate makes the resolver throw, and every helper with it: it is never served as
  the guard's user.
- Two revocations of the other sessions in one change leave the current session to verify again: the second finds
  nothing counting to keep. A failure between the commit and the restamp does the same. Both fail closed.
- A `PendingContext` that contradicts itself is refused with an `InvalidArgumentException` when it is built, so one
  that exists is consistent.

## Seams Left

- `PendingCompletion` and `StepUp` defaults come with verification, which will hand a successful proof to them; until
  then a verification on a pending session records no proof.
- The `mfa` middleware judges the structured requirement only once the middleware is replaced; until then the
  `SessionTransition` default leaves it to the newest proof's age.

## Implementation Anchors

- `src/Contracts/`: one file per contract.
- `src/Context/PendingContext.php`, `src/Passkeys/PasskeyAssertion.php`.
- `src/Context/ContextBindings.php`, `src/Seams/SeamBindings.php`, `src/Passkeys/PasskeyBindings.php` and the
  `*Bindings` class of each capability: the defaults.
- `src/Context/CallerContextResolver.php`, `src/Context/SessionFirstFactor.php`.
- `src/Attempts/ChallengeCounters.php`, `src/Passkeys/PasskeyChangeGate.php`: the reverse calls.
- `src/Testing/Seams/`: the contract kits, with their traits in `Concerns/`.

## Authoritative Tests

- `tests/Unit/Context/PendingContextTest.php`
- `tests/Unit/Passkeys/PasskeyAssertionTest.php`
- `tests/Unit/Requirements/RequirementBindingsTest.php`
- `tests/Unit/Requirements/ProofRequirementCheckTest.php`: an external reauthentication mapped as above gives no
  assurance.
- `tests/Unit/Testing/Seams/`: every default meets its kit, and each kit rejects a faulty implementation.
- `tests/Unit/Context/CallerContextResolverTest.php`, `tests/Feature/Context/PendingActionsTest.php`: a pending session
  gets nothing for an action it does not allow.
- `tests/Unit/Proofs/GenerationSessionRevokerTest.php`, `tests/Unit/Attempts/ChallengeCountersTest.php`,
  `tests/Integration/Database/ParallelChallengeCountersTest.php`.

## Change Triggers

- A new seam, or a change to what a contract takes or answers.
- A default changing what it answers, or a seam gaining a default.
- A kit gaining or losing a guarantee.
