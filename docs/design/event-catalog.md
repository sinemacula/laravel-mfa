# Event Catalogue

## Purpose

This note describes the catalogue of events the package's flows dispatch, what each carries, how the context every
event carries is built, and why every event is dispatched only after the change it reports commits.

## Invariants

- Every event is a final readonly class in `Events` extending `Events\ContextEvent`, which implements
  `Contracts\MfaEvent`, so one listener takes them all; the enrolment events extend it through `Events\EnrollmentEvent`,
  and the two recovery code redemption events through `Events\RecoveryCodeRedemptionEvent`.
  The catalogue is listed in [Events](../guides/events.md); its class and field names are stable.
- Every event says what it was for through `MfaEvent::purpose()`: an `Enums\Purpose` field where it varies (codes sent,
  verification, the failure ceiling, lockouts, recovery code use and a low set), `enrollment` for the enrolment events,
  and `null` for a change made outside any verification (renames, preferred factor, removal, reset, lifted lockouts,
  recovery code sets generated or removed).
- An event carries a factor as a `Factors\FactorSummary` (id, type, label, masked destination, status, preferred, last
  use, disabled), never the model, a secret, a code, a provisioning URI, a credential reference or a full destination,
  so a queued listener can serialise it. Who took an action on someone else's factors is an `Events\Actor`, a type and
  an id.
- A factor whose stored state cannot be read (a status the package does not know, or a deadline or disabled time that is
  not a time) has no honest summary, so no event carries it. The one flow that removes such a factor, a reset, counts it
  on `FactorsReset::$unreadableFactors` instead, so the audit trail still records it.
- Verification events carry the purpose and, when the attempt went through a challenge or a passkey's gateway reported
  one, its id, as `CodeSent` does for the challenge it sent. A failure carries the machine-readable
  `Enums\FailureReason`. There is one verification event per attempt, and a check against the whole recovery code set is
  one attempt. A factor missing, foreign or removed under the lock is reported with no factor and no type, so the two
  cannot be told apart. The order against the commit is in
  [Verification Lifecycle and Events](verification-lifecycle-and-events.md).
- The context is an allowlist of scalars (`Events\EventContext::KEYS`): identity type and id, principal type and id,
  tenant id, application, session id, IP address and user agent, `null` when not known. It is read through
  `Contracts\EventContextResolver` and cut down to those keys and to integers and strings by
  `Events\EventDispatcher::context()`, so a resolver cannot put a model in a payload; the application an operation ran
  through names the application.
- The default resolver, `Context\DefaultEventContextResolver`, gives the identity and the IP address and user agent of
  the caller's `Context\ClientContext`, which `CallerContext::fromRequest()` read from the request; it reads no request
  itself. The application is always the one the operation ran through. It never gives the Laravel session's id, a
  bearer secret. An operator's action (a reset or an unlock) carries the client it is given, or none.
- `Events\EventDispatcher::dispatch()` is the one way the package dispatches an event: at once when the storage
  connection has no open transaction, when that transaction commits otherwise, and never when it rolls back. A
  transaction on another connection neither delays nor drops it. The transactions manager is read when the event is
  dispatched, so the testing traits' manager, which ignores their wrapping transaction, is honoured. No other class
  reaches Laravel's dispatcher, by its contract, its class, its facade, its container key, the `Dispatchable` trait or
  the `event()` helper, but `Proofs\ProofBindings`, which only registers the sign-in listeners on it.
- An event dispatched inside a nested transaction runs ahead of those its outer transaction dispatched, however early,
  as the nested one commits first. A flow that nests a transaction inside its own, as `RecoveryCodeService::generate()`
  does, therefore dispatches from outside it, so the events of an enrolment keep the order
  [Enrolment](enrollment.md) sets out.
- Events report; they never enforce. Nothing security-relevant depends on a listener running.
- The package's services dispatch the events, behind the manager, rather than leaving it to the code that calls them, so
  audit subscribers do not rely on an application's cooperation. Audit goes through these events to whatever listens,
  `laravel-audit-log` among them: the package keeps no audit log of its own.

## Success Path

- A flow builds the context once (`$events->context($identity, $application)`), makes its change in its transaction,
  and dispatches each event it owes through `$events->dispatch(...)`; the listeners run once the change commits.

## Failure / Edge Cases

- A change that rolls back dispatches none of its events.
- A resolver that returns a model, an array or a key outside the allowlist has it dropped, never passed on.
- Without a request (a queue job or a console command), the resolver is handed none, and the request's keys are
  `null`.

## Implementation Anchors

- `src/Events/`: the event classes, `ContextEvent`, `Actor`, `EventContext`, `EventDispatcher`, `EventBindings`.
- `src/Contracts/MfaEvent.php`, `src/Contracts/EventContextResolver.php`.
- `src/Context/DefaultEventContextResolver.php`.
- `src/Factors/FactorSummary.php`: the summary and its masking.

## Authoritative Tests

- `tests/Unit/Events/EventCatalogTest.php` `testNoEventCarriesASecretACodeAUriOrAFullDestination`,
  `testEveryEventSaysWhatItWasFor`
- `tests/Unit/Events/EventDispatcherTest.php` `testARollbackDispatchesNothing`
- `tests/Unit/Architecture/NamespaceDependenciesTest.php` `testOnlyTheEventDispatcherReachesLaravelsDispatcher`
- `tests/Unit/Documentation/DocumentationTest.php` `testEveryEventIsInTheEventsTable`,
  `testEveryEventContextKeyIsDocumented`
- `tests/Unit/Events/EventContextTest.php`
- `tests/Unit/Context/DefaultEventContextResolverTest.php`

## Change Triggers

- A new event: a class in `Events` extending `ContextEvent`, its purpose, a row in the events guide (which
  `DocumentationTest` requires), and a row in the catalogue test.
- A new context key: `EventContext::KEYS`, the guide (which `DocumentationTest` requires) and the resolvers.
- Any change to when events are dispatched relative to the transaction.
