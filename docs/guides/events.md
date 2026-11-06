# Events

## The catalogue

Every event the package dispatches is a class in `SineMacula\Laravel\Mfa\Events`:

| Event                          | Fired when                                                                  | Payload                                                        |
|--------------------------------|-----------------------------------------------------------------------------|----------------------------------------------------------------|
| `EnrollmentStarted`            | An enrolment starts: a pending factor awaits confirmation                   | `factor`                                                       |
| `FactorConfirmed`              | A pending factor is confirmed, and so becomes usable                        | `factor`                                                       |
| `EnrollmentAbandoned`          | An enrolment is restarted, cancelled or out of confirmation attempts        | `factor`                                                       |
| `EnrollmentExpired`            | An enrolment's grant expires before it was confirmed                        | `factor`                                                       |
| `BootstrapEnrollmentCompleted` | A factor is confirmed during a pending sign-in by an identity that had none | `factor`                                                       |
| `PasskeyAssociated`            | A passkey is associated with the identity as a factor                       | `factor`                                                       |
| `FactorRenamed`                | A factor is given a new label                                               | `factor`, `previousLabel`                                      |
| `PreferredFactorChanged`       | The identity chooses another preferred factor                               | `factor`, `previous`                                           |
| `FactorRemoved`                | A factor is removed, by the identity or by someone else                     | `factor`, `actor`                                              |
| `FactorDisabled`               | A factor, or the identity's run, reaches the failure ceiling                | `factor`, `purpose`                                            |
| `FactorsReset`                 | Someone resets the identity's factors                                       | `actor`, `reason`, `reenrollmentRequired`, `unreadableFactors` |
| `LockoutApplied`               | Failed attempts lock a factor, or the identity across its factors           | `factor` (null for the identity), `lockedUntil`, `purpose`     |
| `LockoutLifted`                | A lockout is lifted before it ends                                          | `factor` (null for the identity), `actor`                      |
| `CodeSent`                     | A code is sent by SMS or email                                              | `factor`, `purpose`, `challengeId`                             |
| `VerificationPassed`           | An attempt passes, once per attempt                                         | `factor`, `type`, `purpose`, `challengeId`                     |
| `VerificationFailed`           | An attempt fails, once per attempt                                          | `factor`, `type`, `purpose`, `reason`, `challengeId`           |
| `RecoveryCodesGenerated`       | A new recovery code set replaces any earlier one                            | `count`, `generation`, `actor`                                 |
| `RecoveryCodeUsed`             | A recovery code is redeemed                                                 | `remaining`, `purpose`                                         |
| `RecoveryCodesLow`             | A redemption leaves the set at or below its low count                       | `remaining`, `purpose`                                         |
| `RecoveryCodesRemoved`         | The identity's recovery code set is removed                                 | `actor`                                                        |

Verification dispatches `CodeSent`, once for every code sent, resends included and whichever gateway sent it, and
`VerificationPassed` and `VerificationFailed`, once per attempt: a check against the whole recovery code set is one
attempt (see [Verification](verification.md)). `LockoutApplied`, `LockoutLifted` and `FactorDisabled` are dispatched by
the attempt caps (see [Attempts and lockouts](attempts.md)), and the recovery code events by the set's own flows (see
[Recovery codes](recovery-codes.md)).

The enrolment flow dispatches its events in the order [Enrolment](enrollment.md#events) sets out, and the lifecycle flow
in the order [Factor lifecycle](lifecycle.md#events) sets out.

The names of the events and of their fields are stable once released. `factor` is a `Factors\FactorSummary` (id, type,
label, masked destination, status, preferred, last use, disabled), `previous` another; `purpose` is an `Enums\Purpose`
(`sign_in`, `step_up`, `enrollment` and `reauthenticate`); `reason` an `Enums\FailureReason`; `actor` an `Events\Actor`
(type and id), set when someone other than the identity took the action; `challengeId` the challenge a code or an
attempt went through, when it went through one; `type` the type proved or tried (`recovery_code` for a recovery code).

Every event also says what it was for through `$event->purpose()`: the purpose of the attempt, code or proof behind it
for the events that carry a `purpose` field, `enrollment` for the enrolment events (from `EnrollmentStarted` to
`PasskeyAssociated` in the table), and `null` for a change made outside any verification, such as a rename, a removal,
a reset or a new recovery code set. A listener can tell a sign-in recovery from a step-up one by it.

## Context

Every event implements `Contracts\MfaEvent` and carries its context in `$event->context` (also `$event->context()`): who
and what it is about, as scalar values under the same keys every time, which are stable once released, `null` for one
not known:

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

One listener can take every event, since each implements the one contract:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;

Event::listen(MfaEvent::class, function (MfaEvent $event): void {
    // $event->context(), $event->purpose()
});
```

To audit them with `sinemacula/laravel-audit-log`, map the contract rather than listening. `laravel-iam` does this
itself. Without it, register an `EventMapper` that sets an explicit code on the record, because an audit code is never
derived from a class name:

```php
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;

final class MfaAuditMapper implements EventMapper
{
    public function map(object $event, PendingRecord $record): ?PendingRecord
    {
        return match (true) {
            $event instanceof VerificationPassed => $record->event('mfa.verification_passed'),
            default                              => null,
        };
    }
}

AuditLog::map(MfaEvent::class, MfaAuditMapper::class);
```

This is the mapping that package has agreed, ahead of its first release, so check the namespaces against its own
documentation once it is released.

The context is read through `Contracts\EventContextResolver`, handed an `Events\EventSubject`: the identity, the
application the operation ran through, the sign-in it was bound to, and the client it was served to. The sign-in is this
package's own id, the session id a proof binding or a pending session carries, given only where the operation captured
one: a verification, a challenge, an enrolment, a passkey registration, a recovery code redemption or set, and a factor
removed from a session. An operator's action, an attempt's lockout and a rename name none. Alone, the package's default
gives the identity and the client's IP address and user agent; it leaves the session unknown, since its sign-in id is no
session of any authentication layer, and never gives the Laravel session's id, which is a bearer secret. An
authentication layer's adapter binds its own, which maps the sign-in to its session, principal and tenant, and leaves
them unknown when none is given rather than read whichever session the process serves. The application is always the one
the operation ran through, whatever a resolver answers. Whatever a resolver returns is cut down to the keys above and to
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
