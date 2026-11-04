# Factor lifecycle

A factor is listed, removed, reset by someone else, or unlocked through the `Mfa` facade, and records that no longer
serve any purpose are pruned. Every class name below is relative to `SineMacula\Laravel\Mfa`. Enrolling a factor,
renaming it and choosing the preferred one are in [Enrolment](enrollment.md). Cookie-authenticated routes that change
factors need CSRF protection (see [CSRF protection](middleware.md#csrf-protection)).

## Listing and getting factors

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

Mfa::factors();          // list<FactorSummary>, the preferred first, then by id
Mfa::factor($factorId);  // ?FactorSummary
```

Both serve an active session, and a pending one whose credential allows `mfa.list_factors`. A request that serves nobody
gets `[]` and `null`, and an id that is another person's gets the same answer as one that does not exist. Reads go to
the write connection on every call, so a replica behind a removal cannot answer them.

Every factor is listed, pending ones and those enrolled through another application included, since no application hides
another's. A summary holds the id, type, label, masked destination, status, whether it is preferred, last use and
whether the failure ceiling disabled it, and never a secret. `disabled: false` does not mean the factor is offered: what
the application accepts, the combination policy and a passkey's availability decide that too (`Mfa::offeredFactors()`
answers it). Whether a person is set up is whether any of their factors is confirmed; the identity's own
`isMfaEnabled()` answers the same.

## Removing a factor

```php
$result = Mfa::removeFactor($factorId);

if (!$result->wasMade()) {
    return response()->json(['reason' => $result->reason->value], 422);
}

$result->factor;       // FactorSummary, as it stood
$result->outstanding;  // ?Requirement the session no longer meets, for an RFC 9470 style answer
$result->completion;   // ?object the bound session revoker returned, such as a pending session's new credential
```

A removal serves active sessions only. The refusals, in the order they are made:

| Reason              | When                                                                                  |
|---------------------|---------------------------------------------------------------------------------------|
| `not_found`         | Nobody is served, or the session is pending                                           |
| `identity_inactive` | The identity is not active                                                            |
| `not_found`         | The id is unknown or someone else's, or the factor came through another application   |
| `not_found`         | The sign-in changed before the lock was held                                          |
| `not_confirmed`     | The factor is pending: cancel its enrolment, or let it expire                         |
| `not_fresh`         | The session is not fresh for `mfa.remove_factor`, or has no sign-in the store knows   |
| `last_factor`       | The bound `LastFactorPolicy` refuses                                                  |

A factor disabled at the failure ceiling, or of a type the application no longer enables, may still be removed by the
application that enrolled it.

Only those checks become a refusal. A revoker or a session transition that fails, a database error, and a model event
that cancels the deletion all throw and roll the removal back, an `OperationRefusedException` thrown by a seam included:
it was not refused, it failed. Anything a listener throws after the commit propagates too, and the removal stays
committed.

### The step-up

The session must be fresh for `mfa.remove_factor`. While the identity has another confirmed factor, the requirement must
also be met on the session's proofs made without the factor being removed, so a step-up with a factor never authorises
its own removal. The requirement judged is the one the bound `FreshnessGate` holds the session to, so a stricter gate
cannot be satisfied by the removed factor alone. A recovery code's proof counts as made without it, where the
requirement accepts one.

"Another confirmed factor" means exactly that, including one disabled at the ceiling or that this application does not
enable. A person who cannot prove the other factor they hold is reset by someone else (see
[Resetting](#resetting-an-identity)); the rule does not relax for them.

### The last factor

The bound `Contracts\LastFactorPolicy` decides whether the factor may go, on the factors the caller hands it: asked
before the lock on a read of them, and again under the lock on the factors as stored, so two removals cannot each see
the other factor. A policy decides on what it is given and takes no factor lock of its own.

The default, `Lifecycle\RequiredFactorPolicy`, refuses while the bound `IdentityRequirement` requires something of the
identity, or any configured application sets `requirement` to `always`, unless another factor remains that some
configured application accepts: confirmed, not disabled at the failure ceiling, of a type an application enables, and,
for a passkey, with an association that matches it. An identity's only factor stays even when it is itself unusable, as
required MFA could otherwise be turned off with a recovery code. It knows nothing of tenants; bind your own to consult a
tenant's policy too.

### What a removal does

In one transaction under the identity's lock: the factor and its passkey association go; every proof made with it stops
counting on this session; with the last confirmed factor the recovery code set goes; the identity's other sessions are
revoked through the bound `SessionRevoker`, told the factor and the sign-in the removal is made from; this session's
requirement is evaluated again on the proofs it kept, the active tenant's included, and a shortfall goes to the bound
`SessionTransition`, unless the revoker judged the session again itself; `FactorRemoved` is queued, then
`RecoveryCodesRemoved` when there was a set. A pending factor left behind does not keep the set; a confirmed one the
ceiling disabled does.

`$result->outstanding` is the whole requirement the session no longer meets, not what is left of it, as this package
assesses it. An authentication layer's revoker that judged the session itself (see
[Seams with an authentication layer](extending.md#seams-with-an-authentication-layer)) may have ended it or returned it
to pending by rules of its own; what it returned, in `$result->completion`, is the outcome to answer with. Nothing is promoted
when the preferred factor goes: removing it leaves none preferred, and offers fall back to the oldest.

Forgetting the proofs happens at once and is not undone if the change rolls back, which leaves the session to verify
again. Restoring them could undo a later invalidation.

A session left short is held to the whole requirement on its next request through the `mfa` middleware, which judges
the structured requirement against the proofs that remain: a recent weaker proof does not pass once the stronger factor
it stood beside is gone. See [Route middleware](middleware.md).

## Resetting an identity

A person who has lost every factor and their recovery codes is reset by someone else, never through the sign-in flow:

```php
use SineMacula\Laravel\Mfa\Events\Actor;

Mfa::resetIdentity($user, Actor::of($agent), 'Lost phone, identity checked by support.');
Mfa::resetIdentity($user, Actor::of($agent), $reason, requireReenrollment: false);
```

Who may reset whom is the application's authorisation, and any identity proofing its process; the helper checks neither,
and needs no session, so a console command or a queued job can call it. A blank reason is an `InvalidArgumentException`
before anything is written, and a machine identity is refused as `machine_identity`. An inactive identity can be reset.
The last factor policy does not apply.

In one transaction, in this order: every lockout is lifted and the identity's failures in a row cleared; every factor
and enrolment goes, whichever application made it, with its passkey association and proofs; the recovery code set goes;
the re-enrolment obligation is written as stated, so `false` clears one an earlier reset left; the verification
generation advances, whatever the bound revoker does; and every session is revoked through the bound `SessionRevoker`,
last, as the lock order puts the session row after the rest. Delivered code rows stay, since the send caps read them;
with the factor gone they verify nothing.

Resetting the identity the request serves invalidates its own proofs too: none are kept for it. Without an
authentication layer the Laravel login itself goes on, and its next protected request finds no proof.

Once it commits the events follow, in this order: `LockoutLifted` for each live lockout, naming the actor; in id order,
`FactorRemoved` naming the actor for a confirmed factor and `EnrollmentAbandoned` for a pending one;
`RecoveryCodesRemoved` when there was a set; and `FactorsReset`, with the actor, the reason, whether re-enrolment is
required and `unreadableFactors`.

A reset is the remedy for a factor whose stored state cannot be read: a status the package does not know, or a deadline
or disabled time that is not a time. Such a factor makes verifying, listing and removing it throw, so the person cannot
pass, but a reset removes every factor of the identity whatever its state. One whose state cannot be read is never read
for a lift, so its deadline goes with its row, and no status or confirmation is invented for it: it has no
`FactorRemoved` or `EnrollmentAbandoned` of its own, and `FactorsReset::$unreadableFactors` counts it, so the audit trail
still records it.

### Racing a verification

A reset and a verification serialise on the identity's lock. Whichever takes it first, no proof outlives the reset:

- The reset wins: the verification finds its factor gone and fails as `not_found`, and a recovery code finds no set.
- The verification commits first: it stays a success, which nothing can undo, but its proof stops counting with the
  reset.

An enrolment grant from before a reset confirms nothing after it, as its row is gone.

### The re-enrolment obligation

A reset states whether the identity must enrol again at its next sign-in, by default yes. The obligation is durable,
held on the identity's state row, requires an additional verification in every application whatever its own setting, and
ends when a factor is confirmed (see [Requirements](requirements.md) and [Enrolment](enrollment.md)). The next sign-in
therefore enrols through the bootstrap path where it is enabled, or is refused. Without an obligation it proceeds as for
an identity with no factor.

### Self-service recovery

`Contracts\SelfServiceRecovery` lets an application offer its own recovery, such as a delayed reset with notice to the
person. The default, `Lifecycle\NoSelfServiceRecovery`, offers none, and starting one is refused as
`self_service_recovery_unavailable`. Nothing in the package calls it and there is no sign-in path to it: the application
resolves the seam from its own flow, and an implementation resets through `Mfa::resetIdentity()`.

## Unlocking

```php
Mfa::unlockFactor($user, $factorId, Actor::of($agent));
Mfa::unlockIdentity($user, Actor::of($agent));
```

Each answers whether a live temporary lockout was lifted, and reports `LockoutLifted`, naming the actor, when one was.
An id that is not one of the identity's factors answers `false`, reporting nothing. `false` from `unlockIdentity()` does
not mean nothing changed: the identity's count within the current window is cleared even with no lockout live.

Only temporary lockouts lift. Failures in a row are kept, since only a success resets them, so the next failure locks
again, and a factor disabled at the failure ceiling stays disabled until another factor is proved, it is rebound, or the
identity is reset. The lower-level helpers are in [Attempts and lockouts](attempts.md).

## Pruning

```php
Mfa::prune();                                           // PruneResult: enrollments, codes, recoveryCodes, attempts

$schedule->command('mfa:prune')->daily();               // prints how many of each kind went
$schedule->call(fn () => Mfa::prune())->daily();        // or the helper itself
```

The package schedules nothing itself. `lifecycle.prune_after_days` (1 to 3650, default 30) is how long a record is kept
after it stops being usable:

| Record          | Deleted                                        | How                                   |
|-----------------|------------------------------------------------|---------------------------------------|
| Enrolments      | Past `expires_at` by the retention             | One at a time, under its owner's lock |
| Delivered codes | Past `expires_at` by the retention             | Limited deletes                       |
| Recovery codes  | Used or replaced longer ago than the retention | Limited deletes                       |
| Throttle rows   | Their window has ended, with no retention      | Limited deletes                       |

An enrolment is read again under its owner's lock, so one confirmed or restarted meanwhile is left alone. If its factor
is still pending, both go and `EnrollmentExpired` reports it once that commits, its context holding only what the row
says: the owner and the application, never whichever session or tenant the process happens to serve. If the factor is
confirmed or gone, the enrolment row goes alone and nothing is reported. A model event that cancels a deletion there
rolls that enrolment back and throws.

The others are mass deletes in statements of at most a thousand rows, each carrying its conditions, so a row that stops
matching meanwhile stays, and they fire no model event. Retention is at least a day and the longest send window is a
day, so no send cap is shortened. A throttle row whose window has ended counts nothing, so deleting it lifts nothing.

## Events

| Change  | Events, in order                                                                                            |
|---------|-------------------------------------------------------------------------------------------------------------|
| Removal | `FactorRemoved`, then `RecoveryCodesRemoved` with the last confirmed factor where a set existed             |
| Reset   | Each `LockoutLifted`, each `FactorRemoved` or `EnrollmentAbandoned`, `RecoveryCodesRemoved`, `FactorsReset` |
| Unlock  | `LockoutLifted`, for a live lockout                                                                         |
| Prune   | `EnrollmentExpired`, for each pending factor discarded                                                      |

Every one goes through `Events\EventDispatcher`, once its change commits, and none if it rolls back. See
[Events](events.md).

## Seams

| Contract               | Default                                | Bind your own to                                          |
|------------------------|----------------------------------------|-----------------------------------------------------------|
| `LastFactorPolicy`     | `Lifecycle\RequiredFactorPolicy`       | Consult a tenant's policy as well                         |
| `SelfServiceRecovery`  | `Lifecycle\NoSelfServiceRecovery`      | Offer a recovery of your own                              |
| `SessionRevoker`       | `Proofs\GenerationSessionRevoker`      | End real sessions, throwing when one cannot be ended      |
| `SessionTransition`    | `Http\MiddlewareSessionTransition`     | Return an active session to pending when it falls short   |
| `ActiveTenantResolver` | `Requirements\NoActiveTenant`          | Name the tenant from validated session context            |
| `FreshnessGate`        | `Requirements\ConfiguredFreshnessGate` | Hold a session to your own freshness                      |
