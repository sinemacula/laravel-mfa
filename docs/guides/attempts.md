# Attempts and lockouts

Every attempt to prove a factor is counted, and too many failures lock the factor, the identity or the IP address out
for a while, before the driver ever sees another guess. The counts live in the database, on the storage connection, so
they hold across servers and need no cache. Nothing here can be turned off: the settings only choose how strict it is.

## What is counted

An attempt is counted against three scopes at once:

| Scope          | Counts                                             | Locks when                                                  | For                                                 |
|----------------|----------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------|
| The factor     | Its failures in a row                              | They reach `factor_limit`, and again at every failure after | `lockout_seconds`                                   |
| The factor     | Its failures in a row                              | They reach `failure_ceiling`                                | Until another factor is proved, a rebind or a reset |
| The identity   | Its failures across every factor and recovery code | `identity_limit` of them fall within `window_seconds`       | `lockout_seconds`                                   |
| The identity   | Its failures in a row, across every factor         | They reach `failure_ceiling`                                | Until one of its factors is proved, or a reset      |
| The IP address | Failures from the address, whoever made them       | `ip_limit` of them fall within `window_seconds`             | The rest of the window                              |

Once the identity's failures in a row reach `failure_ceiling`, each further failure disables the factor it was made
against, and an attempt that names no factor of its own (a recovery code, or a factor that keeps no state) is refused
outright. Guesses spread across several factors and recovery codes are bounded by the ceiling just as guesses at one
factor are.

A locked attempt is refused without reaching the driver, and `Mfa::verify()` answers it as a failure with the `locked`
reason, carrying the time it lifts, or no time for a factor or an identity at the failure ceiling, which does not lift
by itself. A factor that is no longer among the identity's own when the attempt is made (removed in the meantime) is
reported as `not_found`, also without reaching the driver, and is counted nowhere. The IP address is the one the request
resolves through your trusted proxies (`$request->ip()`), counted by the client it stands for: an IPv4 address as
itself, an IPv6 address by its /64 network.

## The counters

| Counter                                    | Where                                      | Reset or expiry                                                                              |
|--------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------------|
| A factor's failures in a row               | `consecutive_failures` on the factor's row | Reset only by a success of that factor, or when the factor is enabled again; never expires   |
| A factor's lockout                         | `locked_until` on the factor's row         | Expires `lockout_seconds` after the failure that applied it; lifted early only by an action  |
| A factor disabled at the failure ceiling   | `disabled_at` on the factor's row          | Ends when another of the identity's factors is proved, or when the factor is enabled again   |
| The identity's run of failures             | `consecutive_failures` on its state row    | Reset by a success of any of its factors or recovery codes, or a reset; never expires        |
| The identity at the failure ceiling        | `consecutive_failures` on its state row    | Ends when its run is reset, by a success of any of its factors or by a reset                 |
| The identity's failures within the window  | A row of `mfa_attempts`, scope `identity`  | Expires with its window, `window_seconds` after the first failure in it; cleared when lifted |
| The identity's lockout                     | `locked_until` on its state row            | Expires `lockout_seconds` after the failure that applied it; lifted early only by an action  |
| An IP address's failures within the window | A row of `mfa_attempts`, scope `ip`        | Expires with its window, `window_seconds` after the first attempt in it                      |
| A sent code's challenge's attempts         | A row of `mfa_codes`, its `attempts`       | Kept across resends and capped at `codes.max_attempts`; ends with the challenge              |

Durable counts are kept on the factor and identity state rows and only a success resets them; a lockout's deadline sits
beside them and ends on its own, and the rate windows in `mfa_attempts` expire on their own. They are kept apart on
purpose: a factor's lockout ending does not forgive its failures, so once a factor has reached `factor_limit`, each
further failure locks it again, one guess per lockout period, until a success resets the count or the failure ceiling
disables the factor.

Three things never reset a count or lift a lockout:

- **Sending or resending a code.** Only a success does, so a resend endpoint is never a free unlock.
- **A refused attempt.** It reaches no driver and is counted nowhere, so hammering a locked factor, identity or address
  does not extend its lockout.
- **A success of another factor.** It resets the counts of the factor proved and the identity's run, and enables the
  identity's factors the failure ceiling disabled; it resets no other factor's count and lifts no lockout or throttle.
  A factor enabled this way keeps its failures in a row, so its next failure disables it again. An application claiming
  an assurance level needs more than this (see [Failure ceiling](compliance.md#failure-ceiling)).

## Who is charged

An attempt is charged to the identity whose own pending or active session made it, and only one of that identity's
factors can be attempted: `Mfa::verify()` looks the factor up within the caller's identity, so another
identity's is not found, before anything is counted. Nobody can
lock an identity out with requests of their own. The IP address is charged whoever is signed in.

## Parallel guesses

The identity's lockout and the factor's lockout are read, the driver is called and the outcome counted in one
transaction holding the identity's factor state lock (see [Storage](configuration.md#storage)), so parallel guesses
against one identity are made one after the other and cannot overrun a cap. The driver is handed the factor as stored
under that lock, so it checks the secret stored now rather than what the request read earlier. A code sent by email or
SMS is checked by the bound challenge gateway instead, against the code sent for the request's sign-in, inside the same
transaction, so its use commits with the count and two requests with the same code cannot both pass. The IP address's
slot is taken before the lock, in one statement, and given back unless the attempt fails and is counted, so parallel
guesses from one address across many identities cannot overrun its cap either.

Both lockouts are on rows the transaction locks, so an attempt finds one another request committed even when you call
`Mfa::verify()` inside a transaction of your own on the storage connection, after it has read. MySQL answers a locking
read with the row as committed, also under its default `REPEATABLE READ`, and PostgreSQL's default `READ COMMITTED` reads
afresh for every statement, so the attempt is refused. Under PostgreSQL's `REPEATABLE READ`, locking a row changed since
your snapshot raises a serialisation failure instead: retry your whole transaction, and the attempt is then refused.

The reads that take no lock can still answer from your snapshot, which is another reason to verify outside a transaction
of your own. `lockout()` is advisory, as below. The IP address's refusal or retry time may be stale, though a slot is
only ever taken by a conditional update, so it never admits past the cap.

## Lifting and enabling

A lockout that has not ended yet, a factor the failure ceiling disabled and an identity at the ceiling are separate
states, cleared by separate operations of the attempt service. Resolve it from the container to build unlocking,
rebinding a factor or resetting an identity on it:

```php
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Events\Actor;

$attempts = app(AttemptService::class);

$attempts->lockout($user, $factor, $request->ip());       // the lockout an attempt would meet now, or null
$attempts->liftLockout($user, $factor, Actor::of($agent)); // lift the factor's lockout early
$attempts->enableFactor($factor);                         // enable a factor disabled at the ceiling
$attempts->resetIdentityFailures($user);                  // clear the identity's failures in a row
```

- `lockout($identity, $factor, $ip)` answers the lockout an attempt would be refused by now, or `null`: its scope, and
  when it ends, or no time at all for a factor disabled at the ceiling or an identity at it. It takes no lock, so it is
  advisory: it answers for that moment only, and inside a transaction of your own may answer from that transaction's
  snapshot. Use it to tell someone what to expect, not to decide anything; every attempt reads the lockouts again under
  the lock.
- `liftLockout($identity, $factor, $actor)` lifts the factor's lockout, or the identity's when no factor is given. It
  keeps the factor's failures in a row and the identity's, so the next failure locks again, and leaves a disabled
  factor disabled. A factor that is not the identity's lifts nothing. It dispatches `LockoutLifted`, naming the actor,
  when a live lockout was lifted, and answers whether one was: a deadline that has already passed is cleared without
  either.
- `enableFactor($factor)` enables a factor the failure ceiling disabled and clears its failures in a row, leaving any
  lockout to end on its own.
- `resetIdentityFailures($identity)` clears the identity's failures in a row, so attempts that name no factor of its
  own are made again. It lifts no lockout and enables no factor.

`Mfa::unlockFactor()` and `Mfa::unlockIdentity()` lift a lockout for an actor, with the factor found by its id under the
identity's lock, and `Mfa::resetIdentity()` clears the lot (see [Factor lifecycle](lifecycle.md)).

Who may call these, and what they report, is the application's to decide; the package checks only that the factor is
the identity's.

## Events

| Event            | When                                                                      |
|------------------|---------------------------------------------------------------------------|
| `LockoutApplied` | A failure locks the factor (`factor` set) or the identity (`factor` null) |
| `LockoutLifted`  | A live lockout is lifted before it ends, with the `actor` who lifted it   |
| `FactorDisabled` | A factor's failures in a row reach the failure ceiling                    |

Each is dispatched once the attempt's transaction has committed (see [Events](events.md)), so a listener that throws
cannot undo the count: the failure, and the IP address's charge for it, stand. The IP address's throttle has no event:
it says nothing about any one identity.

## Limiting the endpoint

These caps bound guessing at a factor; they do not bound load on the endpoint itself. Layer Laravel's `RateLimiter` on
the route that verifies as well:

```php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;

RateLimiter::for('mfa-verify', static function (Request $request): array {
    $identifier = $request->user()?->getAuthIdentifier() ?? $request->ip();

    return [
        Limit::perMinute(10)->by($request->ip() ?? 'unknown'),
        Limit::perMinute(5)->by((string) ($identifier ?: 'unknown')),
    ];
});

Route::post('/mfa/verify', VerifyController::class)
    ->middleware(['mfa.exempt', 'throttle:mfa-verify']);
```

Apply the throttle only to the verification itself. Routes that read state (`Mfa::requirement()`, `Mfa::factors()`) are
called on every request, and would exhaust the bucket without being any sign of an attack.

## Settings

```php
'attempts' => [
    'factor_limit'    => env('MFA_ATTEMPTS_FACTOR_LIMIT', 5),
    'identity_limit'  => env('MFA_ATTEMPTS_IDENTITY_LIMIT', 20),
    'ip_limit'        => env('MFA_ATTEMPTS_IP_LIMIT', 100),
    'window_seconds'  => env('MFA_ATTEMPTS_WINDOW_SECONDS', 900),
    'lockout_seconds' => env('MFA_ATTEMPTS_LOCKOUT_SECONDS', 900),
    'failure_ceiling' => env('MFA_ATTEMPTS_FAILURE_CEILING', 100),
],
```

The bounds are in [Configuration](configuration.md#attempts). The defaults are far below the 100 consecutive failures
NIST SP 800-63B-4 allows: five failures in a row lock a factor for 15 minutes, after which an attacker gets one guess
per lockout, so the ceiling of 100 is reached only after about a day of patient guessing, and then the factor is
disabled.

A factor that keeps no state of its own (one that is not an Eloquent model implementing `EloquentFactor`) has no
failures in a row, no lockout and no ceiling of its own; its attempts are counted against the identity and the IP
address, so the identity's window locks it and the identity's ceiling refuses it, like a recovery code.
