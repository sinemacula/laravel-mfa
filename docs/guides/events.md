# Events

## The catalogue

Every event the package dispatches is a class in `SineMacula\Laravel\Mfa\Events`:

| Event                          | Fired when                                                                  | Payload                                                    |
|--------------------------------|-----------------------------------------------------------------------------|------------------------------------------------------------|
| `EnrollmentStarted`            | An enrolment starts: a pending factor awaits confirmation                   | `factor`                                                   |
| `FactorConfirmed`              | A pending factor is confirmed, and so becomes usable                        | `factor`                                                   |
| `EnrollmentAbandoned`          | An enrolment is restarted, cancelled or out of confirmation attempts        | `factor`                                                   |
| `EnrollmentExpired`            | An enrolment's grant expires before it was confirmed                        | `factor`                                                   |
| `BootstrapEnrollmentCompleted` | A factor is confirmed during a pending sign-in by an identity that had none | `factor`                                                   |
| `PasskeyAssociated`            | A passkey is associated with the identity as a factor                       | `factor`                                                   |
| `FactorRenamed`                | A factor is given a new label                                               | `factor`, `previousLabel`                                  |
| `PreferredFactorChanged`       | The identity chooses another preferred factor                               | `factor`, `previous`                                       |
| `FactorRemoved`                | A factor is removed, by the identity or by someone else                     | `factor`, `actor`                                          |
| `FactorDisabled`               | A factor reaches the failure ceiling and is disabled                        | `factor`, `purpose`                                        |
| `FactorsReset`                 | Someone resets the identity's factors                                       | `actor`, `reason`, `reenrollmentRequired`                  |
| `LockoutApplied`               | Failed attempts lock a factor, or the identity across its factors           | `factor` (null for the identity), `lockedUntil`, `purpose` |
| `LockoutLifted`                | A lockout is lifted before it ends                                          | `factor` (null for the identity), `actor`                  |
| `CodeSent`                     | A code is sent by SMS or email                                              | `factor`, `purpose`, `challengeId`                         |
| `VerificationPassed`           | An attempt passes, once per attempt                                         | `factor`, `type`, `purpose`, `challengeId`                 |
| `VerificationFailed`           | An attempt fails, once per attempt                                          | `factor`, `type`, `purpose`, `reason`, `challengeId`       |
| `RecoveryCodesGenerated`       | A new recovery code set replaces any earlier one                            | `count`, `generation`, `actor`                             |
| `RecoveryCodeUsed`             | A recovery code is redeemed                                                 | `remaining`, `purpose`                                     |
| `RecoveryCodesLow`             | A redemption leaves the set at or below its low count                       | `remaining`, `purpose`                                     |
| `RecoveryCodesRemoved`         | The identity's recovery code set is removed                                 | `actor`                                                    |

The flows that dispatch them are built over the package's enrolment, verification, recovery code and lifecycle
capabilities; until each flow ships, its events are declared but not yet dispatched, and the earlier
`MfaChallengeIssued`, `MfaVerified`, `MfaVerificationFailed`, `MfaFactorEnrolled` and `MfaFactorDisabled` events,
described in [the lifecycle events design note](../design/verification-lifecycle-and-events.md), are dispatched instead.
`CodeSent` is dispatched already, once for every code the package sends, resends included, with the id of the code's
challenge (see [Delivered Codes](../design/delivered-codes.md)).

The names of the events and of their fields are stable. `factor` is a `Factors\FactorSummary` (id, type, label, masked
destination, status, preferred, last use), `previous` another; `purpose` is an `Enums\Purpose` (`sign_in`, `step_up`,
`enrollment` and `reauthenticate`); `reason` an `Enums\FailureReason`; `actor` an `Events\Actor` (type and id), set when
someone other than the identity took the action; `challengeId` the challenge a code or an attempt went through,
when it went through one; `type` the type proved or tried (`recovery_code` for a recovery code).

Every event also says what it was for through `$event->purpose()`: the purpose of the attempt, code or proof behind it
for the events that carry a `purpose` field, `enrollment` for the enrolment events (from `EnrollmentStarted` to
`PasskeyAssociated` in the table), and `null` for a change made outside any verification, such as a rename, a removal,
a reset or a new recovery code set. A listener can tell a sign-in recovery from a step-up one by it.

## Context

Every event implements `Contracts\MfaEvent` and carries its context in `$event->context` (also `$event->context()`): who
and what it is about, as scalar values under the same keys every time, `null` for one not known:

| Key              | Holds                                                            |
|------------------|------------------------------------------------------------------|
| `identity_type`  | The identity's morph class (or class name)                       |
| `identity_id`    | The identity's key, as a string                                  |
| `principal_type` | The principal the identity acts as, with an authentication layer |
| `principal_id`   | Its id                                                           |
| `tenant_id`      | The active tenant's id, with an authentication layer             |
| `application`    | The application the action went through                          |
| `session_id`     | The session's public id, with an authentication layer            |
| `ip`             | The request's IP address                                         |
| `user_agent`     | The request's user agent                                         |

One listener takes every event and attributes each the same way:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;

Event::listen(MfaEvent::class, function (MfaEvent $event): void {
    AuditLog::record(event: $event::class, context: $event->context());
});
```

The context is read through `Contracts\EventContextResolver`. Alone, the package's default gives the identity, the
application a bound `Contracts\ApplicationResolver` names, and the request's IP address and user agent; it never gives
the Laravel session's id, which is a bearer secret. An authentication layer's adapter binds its own, which also knows
the principal, the active tenant and the session. Whatever a resolver returns is cut down to the keys above and to
integers and strings, so a model or an array returned by mistake never travels in a payload.

## What events never carry

No event carries a factor model, a secret, a code, a provisioning URI, a credential reference or a full destination,
so a queued listener can serialise any of them safely: a factor travels as its summary, with its destination masked.

## After the commit

The package dispatches an event once the change it reports has committed on the storage connection: at once when no
transaction is open there, when that transaction commits otherwise, and never when it rolls back, so a listener never
sees an event for a change that did not happen. A transaction open on another connection neither delays nor drops it.

Events report; they never enforce. Revoking sessions, invalidating proofs and refusing a change are calls the package
makes inside the change, so nothing security-relevant depends on a listener running.
