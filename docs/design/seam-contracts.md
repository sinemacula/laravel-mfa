# Seam Contracts

## Purpose

This note lists the contracts the package declares for the seams between it, an authentication layer and the
application: what each answers, what a fail-closed answer is, the default bound for each, what the authentication
layer provides for each, and the calls it makes back into this package. They are declared together, ahead of the flows
that call them, so the flows can be built against one fixed set. Each public name of `laravel-authentication` a seam
meets is in [Seams with an authentication layer](../guides/extending.md#seams-with-an-authentication-layer).

## Invariants

- Every seam is this package's own contract in `Contracts`, taking and returning this package's values (`Proof`,
  `ProofBinding`, `Requirement`, `Evaluation`, `VerificationResult`, `Channel`, `PendingContext`, `PasskeyAssertion`),
  never a class of another package. An adapter translates between the two.
- An answer that cannot be given safely is the refusing one: `null` for an unknown first factor, no reauthentication or
  no pending session, `false` for a passkey gateway that is unavailable or a factor that may not be removed, and "not
  fresh" for an operation with no setting or a session with no record.
- A call that changes state (`SessionRevoker`, `SessionTransition`) reports a refusal or a failure by throwing, never by
  returning: a session that cannot be ended or judged again. Returning means it was done, and a throw rolls back the
  factor state change the call runs in.
- `SessionTransition::factorChanged()` judges the current session again after every factor change on an active session
  (a factor confirmed, a passkey registered as a factor, a removal its revoker left to the package), whether or not the
  package finds it short, with a `Requirements\SessionChange`: the identity, the application, the sign-in, what was done
  (`Enums\FactorChangeMade`), the factor, and the package's own assessment, the requirement the session no longer meets
  or `null`. The assessment is information, not a verdict. It runs after the package's locks and writes, and what it
  returns reaches the caller as the change's `completion()`. A session it ended, or found ended, is a return, not a
  refusal.
- `FactorChangeGate` authorises a change to a person's factors from an active session (a first additional factor, a
  further one, a removal, recovery codes), asked inside the identity's transaction after the package's locks and never
  before them, with a `Requirements\FactorChangeRequest`: the identity, the application, the sign-in, the change, the
  factors as stored under the lock, the factor a removal names, and the requirement the application configures for the
  change's operation, which the gate must apply as well as its own policy. It refuses by throwing an
  `OperationRefusedException`, which a bound gate's caller receives as the package's refusal; for a grant it answers
  the instant the grant ends, and the package refuses one that is `null` or not in the future. It replaces the
  package's freshness judgement of those changes, so the package asks no `FreshnessGate` for them besides it.
- `PendingCompletion` and `StepUp` are the last write of a verification's transaction, and refuse by throwing an
  `OperationRefusedException` with a reason, which rolls the verification back and is answered as a failed result;
  anything else they throw propagates. Returning means the proof was accepted, a session still pending included, and
  what they return is opaque to this package and reaches the caller as `VerificationResult::completion()`, so an
  authentication layer's tokens need no request state kept anywhere and no reference to a sibling class. Turning that
  layer's refused result into a throw is the adapter's job. The rollback holds only when the adapter's writes share the
  storage connection.
- Results cross the seams as structured values, never reduced to `amr`.
- Every seam has a default that works without an authentication layer and fails closed, bound by the `*Bindings` class
  of the capability whose state it reads (or `Seams\SeamBindings` for one that reads nothing of the package) only when
  nothing is bound yet, so a binding made before the package's provider is kept and one made after replaces it.
  `SelfServiceRecovery` is bound to `Lifecycle\NoSelfServiceRecovery`, which offers none; nothing in the package
  resolves it, and an application's own flow does. `ApplicationResolver` has no binding: without one, the application
  is the guard's name.
- `PendingCompletion` and `StepUp` are both bound to `Proofs\ProofStoreCompletion`, which records the proof in the bound
  proof store once the transaction commits, refusing a binding that is not the store's current sign-in, and for a
  pending session the pending context's as well, as `not_accepted` (see [Proof Store](proof-store.md)).
- `EventContextResolver` is bound to `Context\DefaultEventContextResolver`, which gives the identity, the application
  and the caller's client (see [Event Catalogue](event-catalog.md)).
- `ProofStore` is bound to `Proofs\SessionProofStore`, which keeps each sign-in's proofs in the Laravel session (see
  [Proof Store and Sign-Ins](proof-store.md)).
- `CombinationPolicy` is bound to `Assurance\DefaultCombinationPolicy` (see
  [Combination Policy](combination-policy.md)); the default `RequirementCheck` calls it.
- The requirement seams are bound since `Mfa::requirement()`, `Mfa::isFresh()` and the `mfa` middleware call them:
  `RequirementPolicy` to `Requirements\ConfiguredRequirementPolicy`, `IdentityRequirement` to
  `Requirements\IdentityContractRequirement`, `ActiveTenantResolver` to `Requirements\NoActiveTenant`,
  `TenantRequirement` to `Requirements\NoTenantRequirement`,
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
- `ActiveStateResolver` is bound to `Context\IdentityContractActiveState`: an identity is active when its
  `isMfaActive()` is true. The bound resolver is the authority in the same way: an inactive identity is refused every
  operation, offered no factor, meets no requirement, is never fresh and gets the neutral authentication context.
- `FirstFactorResolver` is bound to `Applications\DeclaredFirstFactorResolver`: the application's `first_factor`, for
  an identity with a sign-in on it, as a first factor naming no destination or credential, observing nothing, bound to
  the sign-in under the identity's current verification generation and dated at the Unix epoch. When it was made is not
  known, so it establishes the channel a further factor must be independent of and supplies no freshness of its own.
  The configuration check refuses an application with no declaration while this default is the one bound.
- `Reauthenticator` is bound to `Seams\RefusingReauthenticator`, which never proves the first factor again, so enrolling
  a first additional factor on an active session fails closed until the application binds one.
- `FactorChangeGate` is bound to `Requirements\ConfiguredFactorChangeGate`, which judges a first additional factor on a
  first factor reauthentication through the bound `Reauthenticator`, made on the sign-in under the identity's current
  verification generation within five minutes, and every other change on the bound `FreshnessGate` with the configured
  requirement: a removal on the proofs made without the factor while another confirmed factor remains. Its own
  refusals are marked as the package's, and a refusal a seam it asks throws propagates unmarked.
- `SessionRevoker` is bound to `Proofs\GenerationSessionRevoker`, which advances the identity's verification generation
  (see [Proof Store and Sign-Ins](proof-store.md)). A factor's removal names the factor and the sign-in it is made from;
  the default reads that sign-in's counting proofs, other than the factor's, while the store still names it as current
  (none otherwise), advances the generation inside the change, and once the change commits records those proofs again
  on the same sign-in under exactly the generation it advanced to, only while the store still names that sign-in and
  dropping a refusal. A later revocation in the same change therefore still wins, and a change that rolls back revokes
  nothing. The Laravel sessions themselves go on; the other sessions must verify again. It answers
  `Proofs\RemovalRevocation::othersEnded()`, leaving the current session for the package to judge; a revoker that judges
  it itself answers `judged()` with what the caller is to receive, and the package then hands the removal to no
  `SessionTransition`.
- `SessionTransition` is bound to `Http\MiddlewareSessionTransition`, which changes nothing, because the `mfa`
  middleware is the gate: it works the whole requirement out again on every request and judges the session's proofs
  against it, so a session left short is refused until it meets it again, and the session keeps its proofs, as a pending
  session does (see [Route Gate](route-gate.md)).
- `ChallengeGateway` is bound to `Codes\PackageChallengeGateway`, the package's own delivered codes, owned exactly as an
  authentication layer must own its challenges (see the reverse calls below). It serves only a binding that is exactly
  the caller's own: its identity, its application and its session (the pending session's, or the current sign-in's). A
  request carrying a pending session never reaches an active sign-in of the same identity elsewhere. `send()` answers a
  `Codes\SendResult`, and `verify()` an `Attempts\ChallengeOutcome`: passed, failed and counted, or refused and counted
  nowhere. `CodeSent` and the verification events are dispatched by the verification flow, whichever gateway is bound.
- `PasskeyGateway` is bound to `Passkeys\UnavailablePasskeyGateway`: no passkey is registered, verifying is refused with
  an `OperationRefusedException` that counts nothing, and starting a ceremony is a `LogicException`. The configuration
  check refuses an application that enables `passkey` while it is bound (see [Passkeys](passkeys.md)).
- `LastFactorPolicy` is bound to `Lifecycle\RequiredFactorPolicy`: while the bound `IdentityRequirement`, or any
  configured application set to `always`, requires a factor, the last factor some configured application accepts
  (confirmed, not disabled at the ceiling, of a type an application enables) may not be removed. The caller hands it the
  factor state, so it takes no factor lock of its own (see [Factor Lifecycle](factor-lifecycle.md)).
- Authentication's activation fires Laravel's `Login`, on which `Proofs\BeginSignInOnLogin` calls
  `ProofStore::begin()`. An adapter over authoritative session rows makes `begin()` a no-op for them: activation
  preserves that row's sign-in and proofs, and an actual new sign-in uses a new row. Its transaction order is the
  identity, its factors, the challenge, then authentication's session row. A recovery code's proof has no channel, which
  the adapter maps onto the channel authentication requires.
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

| Contract                 | Answers                                                                      | `laravel-authentication` provides                  |
|--------------------------|------------------------------------------------------------------------------|----------------------------------------------------|
| `CombinationPolicy`      | Whether a factor may follow a first factor, and what proofs establish        | Nothing: this package's own                        |
| `ProofStore`             | The current sign-in and its proofs that still count; forgetting them         | The session's proof records                        |
| `RequirementPolicy`      | What a sign-in must prove after its first factor                             | Its additional-factor requirement, mapped          |
| `IdentityRequirement`    | What the identity itself requires                                            | Nothing: the identity contract                     |
| `TenantRequirement`      | What the active tenant requires                                              | Its tenant policy's requirement                    |
| `ActiveTenantResolver`   | Which tenant applies to the session, from validated session context          | The session's validated tenant, by the adapter     |
| `RequirementCheck`       | Whether a session's proofs meet a requirement                                | Nothing: it calls this package's check             |
| `FreshnessGate`          | Whether the session is fresh enough for a named operation                    | Its freshness policy                               |
| `Reauthenticator`        | The first factor proved again on an active session, or none                  | Its reauthentication with the first factor         |
| `PendingSessionResolver` | The request's pending session, as a `PendingContext`, or none                | Its validated pending credential                   |
| `FirstFactorResolver`    | The first factor's proof on the session, or none when unknown or untrusted   | The session's first-factor proof                   |
| `PendingCompletion`      | Receives a successful verification on a pending session                      | Satisfying the pending session                     |
| `StepUp`                 | Receives a successful verification on an active session                      | Its step-up                                        |
| `ChallengeGateway`       | Sends and checks a delivered factor's codes as bound challenges              | Its `mfa` challenges                               |
| `PasskeyGateway`         | Lists passkeys, and requests and verifies assertions for allowed ones        | Its WebAuthn credentials and ceremonies            |
| `SessionRevoker`         | Ends the identity's other sessions, or all of them, inside a factor change   | Logging out everywhere, optionally but the current |
| `FactorChangeGate`       | Whether an active session may change the identity's factors now              | Its factor-change gate                             |
| `SessionTransition`      | Judges the current session again after a factor change                       | Judging a session after a factor change            |
| `LastFactorPolicy`       | Whether the identity's last factor may be removed                            | Nothing, or a tenant-aware policy of the iam layer |
| `SelfServiceRecovery`    | Whether an application offers its own recovery, and starting it              | Nothing: the application's own                     |
| `SubjectTypeResolver`    | Whether an identity is a person                                              | Its subject type                                   |
| `ActiveStateResolver`    | Whether an identity is active                                                | Its identity's active state                        |
| `ApplicationResolver`    | The application a request is for                                             | The session's application                          |
| `EventContextResolver`   | The scalar context every event carries                                       | Its event context                                  |
| `SmsSender`              | Delivers a code by SMS, given its neutral details as a `Codes\CodeMessage`   | The gateway its own codes are sent through         |
| `EmailSender`            | Delivers a code by email, given its neutral details as a `Codes\CodeMessage` | The gateway its own codes are sent through         |

The reverse calls are the critical enforcement points, made by the authentication layer into this package inside its
own transaction on the storage connection:

| Call                                                  | Made                                                                                  |
|-------------------------------------------------------|---------------------------------------------------------------------------------------|
| `Attempts\ChallengeCounters::isUsable()`              | Before sending or checking an `mfa` challenge: is the factor usable, is it locked     |
| `Attempts\ChallengeCounters::report()`                | With every outcome, in the transaction that consumes the challenge, never later       |
| `Passkeys\PasskeyChangeGate::registering()`           | Before storing a registered passkey: associates it as a factor where enabled          |
| `Passkeys\PasskeyChangeGate::removing()`              | Before deleting a passkey: removes its factor under the removal rules                 |

Both classes refuse with a `LogicException` outside a transaction, so their locks are held until the caller commits; the
lock order is the identity's state, then its factors, then the caller's own challenge or credential. The caller
therefore calls the gate before it takes its session rows, which this repository cannot test for it. A refusal is an
exception that rolls the caller's change back with it.

- `Context\PendingContext` holds a pending session: the identity, the application, the session's public id, the first
  factor's proof, the outstanding requirement and the `PendingAction` cases the pending credential allows. It refuses a
  first factor's proof that is not a first factor or is bound to another identity, application or session, and actions
  that are not a list of pending actions each named once. A helper serves it only an action it `allows()`.
- `Passkeys\PasskeyAssertion` holds what a verified assertion observed: the credential and its `ObservedProperties`.

## Success Path

- An adapter, or the application, implements a contract and binds it in the container from a service provider; the
  flow that calls the contract resolves it when it runs, so a binding made before or after the package's provider
  applies.
- Every self-service helper takes a `Context\CallerContext` first, and no seam is handed a request:
  `CallerContext::fromRequest()` is the one place a caller is read from one, through
  `PendingSessionResolver::fromRequest()` and then the guard. The caller is trusted input, never authentication.
  `Context\CallerContextResolver` decides whether it is served: a pending session only for the `PendingAction` the
  helper needs, as its own identity, and otherwise the identity it names; only a person either way. Under the
  identity's lock, `CallerContextResolver::still()` asks `PendingSessionResolver::revalidate()` for a pending session,
  or the proof store for an active one's sign-in, and compares the binding; a pending session that no longer stands is
  refused. A resolver that must read the credential again keeps it on the `PendingContext`, as `credential()`, which is
  held as a `\SensitiveParameterValue` so no dump shows it. The seams handed the caller are `ChallengeGateway`,
  `StepUp` and `FreshnessGate`; `ChallengeCounters` and `PasskeyChangeGate` take one as well, and `SessionRevoker` is
  handed the application. Starting, resending and cancelling an enrolment need
  `mfa.start_bootstrap_enrollment`, and confirming one `mfa.confirm_bootstrap_enrollment`. A helper that names no action
  (generating recovery codes, renaming, preferring or removing a factor and `proofs()`) serves active sessions only;
  `recoveryCodeStatus()` needs `mfa.list_factors`, as `factors()` and `factor()` do. A bound factor route parameter
  serves a pending session allowing any action that names an existing factor (see
  [Factor Route Binding](factor-route-binding.md)).
- A seam may throw an `OperationRefusedException`. It stays an exception on the two helpers that answer refusals as
  values, `generateRecoveryCodes()` and `requestAssertion()`: only a refusal the package marks becomes the reason, so a
  seam's is never read as the package deciding.
- `FreshnessGate::requirement()` answers what the gate holds a session to, so a removal can judge it on the proofs made
  without the factor; `null` refuses that removal while another factor remains. `FreshnessGate::freshUntil()` answers
  how long `isFresh()`'s answer lasts, or `null`, which refuses what depends on it. `PendingContext::$expiresAt` is the
  pending session's expiry, which a bootstrap grant lives no longer than. Under a binding whose purpose is `enrollment`,
  `ChallengeGateway` is handed a pending factor, `ChallengeCounters::isUsable()` admits only that, and `report()`
  changes no count (see [Enrolment](enrollment.md)).
- `Testing\Seams` holds a contract kit per seam: a trait of tests with abstract hooks, in `Testing\Seams\Concerns`,
  delegating each check to a `*Contract` class of static assertions. This package's tests use the traits to prove its
  defaults and call the assertions on deliberately faulty implementations to prove the kit rejects them; an adapter's
  test case uses the same traits. The kits live in `src/` because a dependent package does not load another's
  development autoloading; they need PHPUnit, as Laravel's own testing helpers do. They check safety guarantees, not
  capabilities a default lacks.

## Failure / Edge Cases

- Resolving `SelfServiceRecovery` or `ApplicationResolver` with nothing bound fails with Laravel's binding error; no
  shipped flow does so.
- A pending credential that does not validate makes the resolver throw, and every helper with it: it is never served as
  the guard's user.
- Two factor removals in one change leave the current session to verify again: the second finds nothing counting to
  keep. A failure between the commit and the restamp does the same, and so does a removal named as made from a sign-in
  that is not the current one. All of them fail closed.
- A `PendingContext` that contradicts itself is refused with an `InvalidArgumentException` when it is built, so one
  that exists is consistent.

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
- `tests/Unit/Requirements/FactorChangesTest.php`, `tests/Unit/Testing/Seams/FactorChangeGateContractTest.php`.
- `tests/Unit/Proofs/GenerationSessionRevokerTest.php`, `tests/Unit/Attempts/ChallengeCountersTest.php`,
  `tests/Integration/Database/ParallelChallengeCountersTest.php`.

## Change Triggers

- A new seam, or a change to what a contract takes or answers.
- A default changing what it answers, or a seam gaining a default.
- A kit gaining or losing a guarantee.
