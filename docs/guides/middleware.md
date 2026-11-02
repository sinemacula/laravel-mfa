# Route middleware

`mfa` is a middleware you place on your own routes. It lets a request on only when the session the request serves meets
its whole requirement, read from the proofs it holds, and otherwise raises `InsufficientAuthenticationException`. Every
class name below is relative to `SineMacula\Laravel\Mfa`.

## The forms

| Form                               | Asks for                                   |
|------------------------------------|--------------------------------------------|
| `mfa`                              | The composed requirement, and adds nothing |
| `mfa:level=aal2`                   | That, and a minimum level                  |
| `mfa:operation=account.delete`     | That, and a named operation's freshness    |
| `mfa:level=aal2,operation=reports` | All of them                                |
| `mfa.exempt`                       | Marks a route `mfa` does not gate          |

```php
Route::middleware('mfa')->group(function () {
    Route::get('/dashboard', DashboardController::class);

    Route::middleware('mfa:level=aal2')->get('/billing', BillingController::class);
    Route::middleware('mfa:operation=account.delete')->delete('/account', DeleteAccountController::class);
});
```

Separate entries, from a group and a route, each enforce their own.

Bare `mfa` is the requirement composed in [Requirements and step-up](requirements.md): what the application's mode asks,
the identity's own part, a re-enrolment obligation and the active tenant's part. `never` adds nothing rather than
letting everyone through, so those other parts still apply. `enrolled` asks nothing of someone with no confirmed factor,
so a shared group does not lock out people who have not opted in. A route that demands verification regardless uses a
level or an operation.

A level has no maximum age. Freshness for a route goes through a named operation, configured in the application's
`freshness` block (see [Requirements and step-up](requirements.md#step-up)) and judged only by the bound
`FreshnessGate`. An operation nobody configured is not a misconfiguration: with the default gate it is never fresh, so
the route answers with the exception. A gate an adapter binds may supply it.

Parameters are checked first, also on an exempt route, so a typo is loud. Each is `key=value`, the keys are `level` and
`operation`, and each may be given once. Anything else raises an `InvalidArgumentException`: an unknown key, a repeated
one, an empty parameter (a trailing comma), an empty value, a second `=`, the `unclassified` level or anything that is
not a level, and an operation that is not in the form an operation's name takes.

## Exempting a route

The routes that complete a verification or a bootstrap enrolment cannot themselves require it. `mfa.exempt` lifts every
form of `mfa` on the route, parameterised ones too, however it reached the route:

```php
Route::middleware(['mfa', 'mfa.exempt'])->post('/mfa/verify', VerifyController::class);
```

It grants nothing: the helpers such a route calls check for themselves. `mfa` reads the marker from the route's resolved
middleware, so the order the two run in does not matter, `withoutMiddleware('mfa.exempt')` is honoured, and nothing a
request carries can claim it. The marker takes no parameters.

With no matched route nothing is exempt, so `mfa` is route middleware only. Do not put it in the global stack.

## Who is refused

There is one exception for every refusal. These hold under `never` too, since that setting controls the requirement and
not who the package serves:

| Caller                                | `requirement` on the exception  | `hasConfirmedFactor`            |
|---------------------------------------|---------------------------------|---------------------------------|
| A pending session on the request      | What it owes, with any level    | The pending identity's          |
| A guest                               | Any level, or nothing           | `false`                         |
| A signed-in identity not MFA-capable  | Any level, or nothing           | `false`                         |
| A machine (see `SubjectTypeResolver`) | Any level, or nothing           | `false`                         |
| An inactive identity                  | The whole requirement, as below | The identity's `isMfaEnabled()` |
| A served person falling short         | The whole requirement           | The identity's `isMfaEnabled()` |

The whole requirement is the composed one, any level and the operation's requirement. A forgotten `auth` therefore
leaves a route closed, not open, and a route machines use does not carry `mfa`. A request carrying a pending credential
is never answered from the guard's user, even with an active credential beside it, and a pending credential that does
not validate reaches you as whatever its resolver throws, not as a refusal.

The gate only reads. It never calls `SessionTransition`, so a GET revokes nothing, and a stale operation is a step-up
rather than a demotion of the whole sign-in. A change that leaves a session short hands that to the transition itself.

## Answering

`InsufficientAuthenticationException` is a 401. It sets no `WWW-Authenticate` header, because the package also serves
cookie guards and RFC 9470 is about a presented access token, and Laravel renders it with its message alone. Choose your
answer in the exception handler:

```php
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;

$this->renderable(function (InsufficientAuthenticationException $e) {
    return response()->json($e->toArray(), 401, ['WWW-Authenticate' => $e->wwwAuthenticate()]);
});
```

`wwwAuthenticate()` gives `Bearer error="insufficient_user_authentication", error_description="...", acr_values="aal2",
max_age="300"`, omitting what is absent. An adapter mapping levels to `acr` names builds its own from the parts:

| Member                | What it is                                                                                      |
|-----------------------|-------------------------------------------------------------------------------------------------|
| `$requirement`        | The whole effective requirement, not what is left of it. The authority                          |
| `$offered`            | The factors the session could use next, as masked `FactorSummary` values                        |
| `$operation`          | The operation the route names, or `null`. Only its name for a caller the package does not serve |
| `$hasConfirmedFactor` | Whether the identity has a confirmed factor                                                     |
| `maxAge()`            | The shortest maximum age of any part, or `null`                                                 |
| `acrValues()`         | The minimum level's value, or none                                                              |
| `toArray()`           | `error`, `max_age`, `acr_values`, `requirement`, `operation`, `has_confirmed_factor`, `factors` |

`maxAge()` and `acrValues()` are lossy: each part of a requirement is bounded on its own, and neither can state
multifactor authentication or phishing resistance. Read `$requirement` where that matters.

The offers are candidates. `Mfa::offeredFactors()` answers which factors can follow the first factor, not which would
meet this requirement, so a refusal asking for AAL2 can offer only an email code.

`$hasConfirmedFactor` is no authority to bootstrap. Having none does not mean enrolment is needed, as a multi-factor
first factor can meet a requirement, and `$offered` being empty can also mean an unknown first factor or every factor
disabled. Enrolling has checks of its own (see [Enrolment](enrollment.md)).

## The authentication context

`Mfa::authenticationContext()`, or `Context\AuthenticationContextContributor::contribute()`, gives these keys for the
`mfa` namespace of the authentication context, always all of them:

| Key                             | Type           | Means                                                                        |
|---------------------------------|----------------|------------------------------------------------------------------------------|
| `accepted`                      | `bool`         | The session meets an additional verification                                 |
| `multifactor`                   | `bool`         | The session's proofs are multifactor authentication                          |
| `factor_types`                  | `list<string>` | The types of its evidence, each once, oldest first                           |
| `level`                         | `string`       | The assurance level its proofs support                                       |
| `phishing_resistant`            | `bool`         | Whether they are phishing-resistant                                          |
| `user_verification`             | `bool`         | Evidence, or a first factor supporting a level, observed the person verified |
| `last_verification_age_seconds` | `?int`         | Whole seconds since the newest evidence, `null` without any                  |
| `has_confirmed_factor`          | `bool`         | Whether the identity has a confirmed factor                                  |

Evidence is each additional factor and recovery code the bound check accepts after the session's one first factor. A
recovery code is named `recovery_code` and sets the age, as it meets an additional verification. These fields say what
was accepted and recorded, not what a policy selected: a bound check may accept a pair yet refuse the set.

`accepted` means the additional-verification requirement is met, including by a first factor that is a multi-factor
authenticator on its own. So a user-verifying passkey reads `accepted`, `multifactor` and an age of `null`, and the gate
and the context agree for the same requirement and proofs. A gate with a freshness or a stronger requirement can still
refuse. The age is not an operation's freshness.

A pending session, a guest, a machine, an identity that is not MFA-capable and an inactive identity get the neutral
context: `false`, `false`, `[]`, `unclassified`, `false`, `false`, `null`, `false`. A pending session's enrolment
information comes through the pending flow.

## Guards and tenants

The package places `mfa` straight after authentication in the middleware priority, so `['mfa', 'auth:api']`
authenticates first and judges the identity `auth:api` selects.

If your application replaces the priority list with `withMiddleware()`, keep that order: authentication and whatever
selects the application or the active tenant must run before `mfa`. Replacing it does not simply fail closed. When the
default guard already holds a strongly authenticated identity, `mfa` passes for it, and `auth:api` then selects another.

## Without an authentication layer

A guard's identity alone supplies no trusted first factor. Without the sign-in hooks or a `FirstFactorResolver`, or an
application declaring its `first_factor`, the gate refuses and the offers may be empty. See [Recorded proofs](proofs.md)
and [Applications](configuration.md#applications).

How it holds together is in [the route gate design note](../design/route-gate.md).
