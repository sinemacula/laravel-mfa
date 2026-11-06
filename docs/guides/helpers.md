# Helpers

Every flow is one call on the `Mfa` facade, and routes and controllers stay yours, which makes their CSRF protection
yours too (see [CSRF protection](middleware.md#csrf-protection)). Every class name below is relative to
`SineMacula\Laravel\Mfa`.

## The caller

Every helper that acts for the person in front of you takes a `Context\CallerContext` first, and no helper reads the
request. Build one at the edge, once per request:

```php
use SineMacula\Laravel\Mfa\Context\CallerContext;

$caller = CallerContext::fromRequest($request);          // through the default guard
$caller = CallerContext::fromRequest($request, 'admin'); // through the guard named
```

`fromRequest()` asks the bound `Contracts\PendingSessionResolver` first, and a pending session it finds is the caller. A
pending credential that does not validate throws, so the request is refused rather than served as the guard's user.
Otherwise the caller is the guard's user, when it is an identity this package serves, and nobody when it is not. The
application is what a bound `Contracts\ApplicationResolver` names for the request, or else the guard's name. The client
is the request's IP address and user agent, which reach the events and the per-address throttle, and the facts a
same-site check reads: its `Origin`, its scheme and host, and the names (never the values) of the headers that carry a
value, lower-cased with underscores read as hyphens, which `carriesHeader()` answers about. Only the address and the
user agent reach events; the rest is for a seam, such as an authentication layer's `PendingCompletion`, that judges a
cookie-borne session.

Away from a request, in a queued job, a console command or a transport of your own, build one from plain values:

```php
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext;

CallerContext::forIdentity($user, 'web', new ClientContext($ip, $userAgent, $origin, $schemeAndHost, $headerNames));
CallerContext::forPending($pending, $client); // a pending session your resolver read
CallerContext::nobody('web');
```

A `CallerContext` is trusted input from your own code: building one authenticates nobody, so build one only for an
identity your application has already authenticated. Each helper still decides whether it serves the caller. It serves
only a person, and a pending session only the actions its credential allows. Under the identity's lock it checks again
that the pending credential still validates, through the resolver's `revalidate()`, or that the proof store's current
sign-in is still the one the action began on. The sign-in is never carried on the caller: it is read from the proof
store, for the identity and the application. The client is optional: when it is left out, the address is unknown and
the per-address throttle is not applied.

## Every helper

A caller holding a pending session is served as that session's identity when its credential allows the action named,
and otherwise nothing. Any other caller is served as the identity it names, when that is a person. "Active only" serves
a pending session nothing, and "not read" takes no account of one.

### Requirements

| Helper                                       | Returns            | Serves               | On a pending session |
|----------------------------------------------|--------------------|----------------------|----------------------|
| `requirement($caller)`                       | `Requirement`      | The signed-in person | Not read             |
| `isFresh($caller, $operation, $requirement)` | `bool`             | The signed-in person | Never fresh          |
| `proofs($caller)`                            | `list<Proof>`      | The signed-in person | Active only          |
| `authenticationContext($caller)`             | The context's keys | The signed-in person | The neutral context  |

### Factors

| Helper                                     | Returns               | Serves               | On a pending session |
|--------------------------------------------|-----------------------|----------------------|----------------------|
| `factors($caller)`                         | `list<FactorSummary>` | The caller           | `mfa.list_factors`   |
| `factor($caller, $factorId)`               | `?FactorSummary`      | The caller           | `mfa.list_factors`   |
| `offeredFactors($caller)`                  | `list<FactorSummary>` | The caller           | `mfa.list_factors`   |
| `renameFactor($caller, $factorId, $label)` | `FactorChange`        | The signed-in person | Active only          |
| `setPreferredFactor($caller, $factorId)`   | `FactorChange`        | The signed-in person | Active only          |

### Verification

| Helper                                           | Returns              | Serves     | On a pending session |
|--------------------------------------------------|----------------------|------------|----------------------|
| `sendCode($caller, $factorId, $purpose)`         | `SendResult`         | The caller | `mfa.send_code`      |
| `requestAssertion($caller, $factorId, $purpose)` | `AssertionRequest`   | The caller | `mfa.verify`         |
| `verify($caller, $submission, $purpose)`         | `VerificationResult` | The caller | `mfa.verify`         |

A recovery code goes through `Mfa::verify($caller, Submission::recoveryCode($code))`, on the one verification path and purpose
rule: there is no separate helper to redeem one.

### Enrolment

| Helper                                      | Returns                  | Serves     | On a pending session               |
|---------------------------------------------|--------------------------|------------|------------------------------------|
| `startEnrollment($caller, $request)`        | `EnrollmentStart`        | The caller | `mfa.start_bootstrap_enrollment`   |
| `confirmEnrollment($caller, $grant, $code)` | `EnrollmentConfirmation` | The caller | `mfa.confirm_bootstrap_enrollment` |
| `resendEnrollmentCode($caller, $grant)`     | `SendResult`             | The caller | `mfa.start_bootstrap_enrollment`   |
| `cancelEnrollment($caller, $grant)`         | `bool`                   | The caller | `mfa.start_bootstrap_enrollment`   |

### Recovery codes

| Helper                           | Returns                  | Serves               | On a pending session |
|----------------------------------|--------------------------|----------------------|----------------------|
| `generateRecoveryCodes($caller)` | `RecoveryCodeGeneration` | The signed-in person | Active only          |
| `recoveryCodeStatus($caller)`    | `?RecoveryCodeStatus`    | The caller           | `mfa.list_factors`   |

### Lifecycle

| Helper                                                            | Returns               | Serves               |
|-------------------------------------------------------------------|-----------------------|----------------------|
| `removeFactor($caller, $factorId)`                                | `FactorRemovalResult` | The signed-in person |
| `resetIdentity($identity, $actor, $reason, $requireReenrollment)` | `void`                | The identity given   |
| `unlockFactor($identity, $factorId, $actor)`                      | `bool`                | The identity given   |
| `unlockIdentity($identity, $actor)`                               | `bool`                | The identity given   |
| `forgetIdentity($identity)`                                       | `void`                | The identity given   |
| `prune()`                                                         | `PruneResult`         | No identity          |

`removeFactor()` serves active sessions only. The others are told the identity by their caller, so who may call them is
your authorisation. `resetIdentity()`, `unlockFactor()` and `unlockIdentity()` also take an optional
`Context\ClientContext` last, the operator's own client, which their events carry.

### Registry

| Helper                     | Returns           |
|----------------------------|-------------------|
| `driver($name)`            | `FactorDriver`    |
| `extend($name, $callback)` | `MfaManager`      |
| `getDefaultDriver()`       | `string`, `totp`  |
| `factorModel()`            | The model's class |

The manager's inherited `getDrivers()`, `getContainer()` and `forgetDrivers()` stay callable as Laravel's
infrastructure, and are not part of this surface. Any other method is refused with a `BadMethodCallException`, rather
than forwarded to the default driver as Laravel's manager would: a driver's own check runs outside attempts, proofs and
events, so `Mfa::driver($name)` is the deliberate way to reach one.

## When a helper refuses

A helper a person can be refused by answers with a value holding the reason, so a stale session is never a 500:

```php
$caller     = CallerContext::fromRequest($request);
$generation = Mfa::generateRecoveryCodes($caller);

if (! $generation->wasGenerated()) {
    return response()->json(['reason' => $generation->reason->value], 403);
}

$assertion = Mfa::requestAssertion($caller, $factorId);

if (! $assertion->hasStarted()) {
    return response()->json(['reason' => $assertion->reason->value], 422);
}

return response()->json($assertion->options);
```

Nobody served is `not_found`, as on `sendCode()` and `removeFactor()`. `cancelEnrollment()`, `unlockFactor()` and
`unlockIdentity()` answer a `bool`, having no reason worth telling. `resetIdentity()` and `forgetIdentity()` are
operator calls, and answer nothing.

On `generateRecoveryCodes()` and `requestAssertion()`, an `Exceptions\OperationRefusedException` a seam of your own
throws is not turned into a value: it is yours, and it propagates, with what the call did rolled back. The other helpers
that answer with a value still report it as their reason: `sendCode()`, `verify()`, `startEnrollment()` and
`confirmEnrollment()`, and `removeFactor()` from its checks, while a revoker or a session transition throwing one rolls
the removal back and propagates (see [Lifecycle](lifecycle.md)). Any other failure propagates from all of them: a
resolver's, a gateway's and a database's.

## Binding a factor to a route

The shipped `Models\Factor` binds through the caller:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;

Route::delete('/factors/{factor}', function (Request $request, Factor $factor) {
    $removal = Mfa::removeFactor(CallerContext::fromRequest($request), $factor->getFactorIdentifier());

    return $removal->wasMade()
        ? response()->noContent()
        : response()->json(['reason' => $removal->reason->value], 403);
})->middleware('auth');
```

A bound factor is found only within the identity of the request's caller, as `CallerContext::fromRequest()` reads it,
and anything else is the same `404` as a factor that does not exist. An application's own factor model opts in beside
`Concerns\ActsAsFactor`:

```php
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;

final class Factor extends Model implements EloquentFactor
{
    use ActsAsFactor, ResolvesFactorRouteBinding;
}
```

On a pending session, a credential binds when it allows `mfa.list_factors`, `mfa.send_code` or `mfa.verify`, as its own
person, and a credential allowing only bootstrap enrolment binds nothing. Binding is an ownership rule, not permission
to run the route: a list-only credential binds on a verify URL, and `Mfa::verify()` then refuses it. Pending factors,
disabled ones and those enrolled through another application all bind, and each helper applies its own rules.

Pass a helper the factor's identifier, `$factor->getFactorIdentifier()`, not the model, which finds nothing, and not
`getRouteKey()`, which a custom key changes.

The limits:

- The caller must be established before `SubstituteBindings` runs. Laravel's middleware priority orders `auth` ahead of
  it. Any other middleware that establishes the credential must be placed ahead of it in the priority list, or the
  factor binds to nobody and answers `404`, or is held to the guard's user rather than the credential the route goes on
  to use.
- A custom key must be unique across identities. With `{factor:type}` the first row found may be another person's, and
  the binding misses. To look a factor up within one identity, go through `Mfa::factors()`.
- A scoped child binding through a parent model (`/users/{user}/factors/{factor}`) is the parent's own lookup, and never
  reaches the trait, so such a route must scope its parent to the caller itself.
- A route that must bind other people's factors uses `Route::bind()`. An administrator does not need one:
  `Mfa::unlockFactor()` and `Mfa::resetIdentity()` take the identity and a raw id.
- A relation eager loaded on another connection is not read from its writer.
