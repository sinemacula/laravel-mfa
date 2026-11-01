# Attempts and Lockouts

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
| The IP address | Failures from the address, whoever made them       | `ip_limit` of them fall within `window_seconds`             | The rest of the window                              |

A locked attempt is refused without reaching the driver, and `Mfa::verify()` reports it as a failure with the `locked`
reason. The IP address is the one the request resolves through your trusted proxies (`$request->ip()`), counted by the
client it stands for: an IPv4 address as itself, an IPv6 address by its /64 network.

## The counters

| Counter                                    | Where                                      | Reset or expiry                                                                              |
|--------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------------|
| A factor's failures in a row               | `consecutive_failures` on the factor's row | Reset only by a success of that factor, or when the factor is enabled again; never expires   |
| A factor's lockout                         | A row of `mfa_attempts`, scope `factor`    | Expires `lockout_seconds` after the failure that applied it; lifted early only by an action  |
| A factor disabled at the failure ceiling   | `disabled_at` on the factor's row          | Ends when another of the identity's factors is proved, or when the factor is enabled again   |
| The identity's run of failures             | `consecutive_failures` on its state row    | Reset only by a success of any of its factors; never expires                                 |
| The identity's failures within the window  | A row of `mfa_attempts`, scope `identity`  | Expires with its window, `window_seconds` after the first failure in it; cleared when lifted |
| The identity's lockout                     | `locked_until` on its state row            | Expires `lockout_seconds` after the failure that applied it; lifted early only by an action  |
| An IP address's failures within the window | A row of `mfa_attempts`, scope `ip`        | Expires with its window, `window_seconds` after the first attempt in it                      |

Durable counts are kept on the factor and identity state rows and only a success resets them; the throttles in
`mfa_attempts` expire on their own. The two are kept apart on purpose: a factor's lockout ending does not forgive its
failures, so once a factor has reached `factor_limit`, each further failure locks it again, one guess per lockout
period, until a success resets the count or the failure ceiling disables the factor.

Three things never reset a count or lift a lockout:

- **Sending or resending a code.** Only a success does, so a resend endpoint is never a free unlock.
- **A refused attempt.** It reaches no driver and is counted nowhere, so hammering a locked factor, identity or address
  does not extend its lockout.
- **A success of another factor.** It resets the counts of the factor proved and the identity's run, and enables the
  identity's factors the failure ceiling disabled; it resets no other factor's count and lifts no lockout or throttle.

## Who is charged

An attempt is charged to the identity whose own pending or active session made it, and only one of that identity's
factors can be attempted: `Mfa::verify()` verifies the current identity's own factor and refuses another identity's
before anything is counted. Nobody can lock an identity out with requests of their own. The IP address is charged
whoever is signed in.

## Parallel guesses

The identity's lockout and the factor's lockout are read, the driver is called and the outcome counted in one
transaction holding the identity's factor state lock (see [Storage](configuration.md#storage)), so parallel guesses
against one identity are made one after the other and cannot overrun a cap. The IP address's slot is taken before, in
one statement, and given back unless the attempt fails, so parallel guesses from one address across many identities
cannot overrun its cap either.

## Lifting and enabling

A lockout that has not ended yet, and a factor the failure ceiling disabled, are separate states, cleared by separate
operations of the attempt service (`Attempts\AttemptService`), which the lifecycle operations (unlocking, rebinding a
factor, resetting an identity) are built on:

- `lockout($identity, $factor, $ip)` answers the lockout an attempt would be refused by now, or `null`: its scope, and
  when it ends, or no time at all for a factor disabled at the ceiling.
- `liftLockout($identity, $factor, $actor)` lifts the factor's lockout, or the identity's when no factor is given. It
  keeps the factor's failures in a row, so its next failure locks it again, and leaves a disabled factor disabled. It
  dispatches `LockoutLifted`, naming the actor, when a live lockout was lifted.
- `enableFactor($factor)` enables a factor the failure ceiling disabled and clears its failures in a row, leaving any
  lockout to end on its own.

## Events

| Event            | When                                                                      |
|------------------|---------------------------------------------------------------------------|
| `LockoutApplied` | A failure locks the factor (`factor` set) or the identity (`factor` null) |
| `LockoutLifted`  | A live lockout is lifted before it ends, with the `actor` who lifted it   |
| `FactorDisabled` | A factor's failures in a row reach the failure ceiling                    |

Each is dispatched once the attempt's transaction commits (see [Events](events.md)). The IP address's throttle has no
event: it says nothing about any one identity.

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

A factor that keeps no state of its own (one that does not implement `EloquentFactor`) has no failures in a row, no
lockout and no ceiling of its own; its attempts are still counted against the identity and the IP address.
