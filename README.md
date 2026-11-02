<h1 align="center">Laravel MFA</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-mfa.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)
[![PHP Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-mfa/php.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-mfa/laravel/framework.svg?label=laravel)](https://packagist.org/packages/sinemacula/laravel-mfa)
[![Build Status](https://github.com/sinemacula/laravel-mfa/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-mfa/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-mfa/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-mfa/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-mfa/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-mfa)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-mfa/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-mfa)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-mfa.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)
[![License](https://img.shields.io/github/license/sinemacula/laravel-mfa.svg)](LICENSE)

</div>

Driver-based multi-factor authentication for Laravel. Ships **TOTP**, **email codes** and **SMS codes** out of the box,
with **recovery codes** as a fallback and a pluggable driver API for custom factor types.

Composes with any authentication stack — SessionGuard, Sanctum, Passport, a custom guard, or
`sinemacula/laravel-authentication`. No runtime coupling to the auth layer: depends only on Laravel's standard
`Authenticatable` contract. Attach middleware to enforce MFA on any route; catch structured exceptions to render
whatever UI you like.

## Features

- **Three built-in factor drivers**: TOTP, email code, SMS code.
- **Recovery codes**: a set of single-use codes shown once, stored as salted hashes, replaced atomically, and redeemed
  as one attempt against the whole unused set. See [Recovery codes](docs/guides/recovery-codes.md).
- **Pluggable driver API**: register custom factor drivers via the Laravel-style `Mfa::extend()` method.
- **Route enforcement middleware**: `mfa` judges a route's whole requirement, `mfa:level=aal2` adds a level, and
  `mfa.exempt` marks the routes that complete a verification. See [Route middleware](docs/guides/middleware.md).
- **Step-up per operation**: `mfa:operation=name` asks for a named operation's freshness on a route.
- **A structured refusal**: `InsufficientAuthenticationException` carries the requirement and masked factor summaries,
  for an answer as RFC 9470 describes or a factor picker.
- **One way to verify**: `Mfa::verify()` takes a factor's code, a challenge's code, a recovery code or a passkey's
  assertion, bound once to the owner, application, sign-in and purpose, and answers with a structured result and a
  machine-readable failure reason. See [Verification](docs/guides/verification.md).
- **Factor lifecycle**: list and remove factors, reset someone who lost theirs with an actor and a reason, unlock, and
  prune what is no longer of use, each change serialised on the identity. See
  [Factor lifecycle](docs/guides/lifecycle.md).
- **Events**: a catalogue of events for the verification, recovery code and lifecycle flows, each carrying a scalar
  context and no secret, dispatched once its change commits (see [Events](docs/guides/events.md)).
- **Polymorphic identity support**: works with any Eloquent identity type (`User`, `Admin`, ...) via the
  shipped `authenticatable_type` / `authenticatable_id` morph.
- **Encrypted at rest**: the factor `secret` column is `encrypted`-cast; recovery codes are stored only as salted
  hashes made with the application's hasher; email and SMS codes are stored only as keyed hashes bound to their factor,
  session, application and purpose, and the package's email code message encrypts its payload whenever it is queued.
- **Secrets shown once**: a value that refuses to be serialised, cast or dumped, which recovery codes and the
  enrolment flow's TOTP secret, provisioning URI and grant are returned in, a response helper and an `mfa.no-store`
  middleware that no cache keeps, and the
  redaction of secrets, codes and full destinations from logs, exception messages and traces, delivery failures
  included (see [Secrets](docs/guides/secrets.md)).
- **Attempt caps and lockouts**: failures are counted per factor, per identity and per IP address in the database, with
  no cache; too many lock the factor, the identity or the address out before the driver is called, and a factor that
  reaches the failure ceiling is disabled. See [Attempts and lockouts](docs/guides/attempts.md).
- **Zero ecosystem coupling**: depends only on Laravel and the standard `Authenticatable` contract.

## Installation

```bash
composer require sinemacula/laravel-mfa
```

Publish the config and migrations, then migrate:

```bash
php artisan vendor:publish --tag=mfa-config
php artisan vendor:publish --tag=mfa-migrations
php artisan migrate
```

## Configuration

The published `mfa.php` config holds one block per application, for what it accepts and offers, and one block per
capability (`totp`, `codes`, `recovery_codes`, `attempts`, `enrollment`, `lifecycle`) for what is the same everywhere:

```php
return [
    'applications' => [
        'web' => [
            'types'        => ['totp', 'email'],
            'requirement'  => 'enrolled',
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ],
    ],

    'codes' => [
        'length'      => 6,  // digits, 6 to 10
        'ttl_minutes' => 10, // 1 to 10
    ],

    'attempts' => [
        'factor_limit'    => 5,
        'lockout_seconds' => 900,
    ],
];
```

Every setting has a production-safe default and enforced bounds. The package checks the whole configuration when it
boots, and `php artisan mfa:check` reports every problem for a deploy pipeline. See
[Configuration](docs/guides/configuration.md) for every key, its default and its bounds, and
[Requirements and step-up](docs/guides/requirements.md) for what a sign-in and a sensitive operation must prove.

> **APP_KEY rotation.** Factor secrets are encrypted at rest via Laravel's `encrypted` cast, so when you rotate
> `APP_KEY`, list the old key in `APP_PREVIOUS_KEYS` for as long as factors enrolled under it exist: a plain swap
> leaves existing factor rows undecryptable. See
> [Rotating the application key](docs/guides/secrets.md#rotating-the-application-key).

Every package table lives on one database connection, `storage.connection` (`MFA_STORAGE_CONNECTION`, the default
connection when `null`), which the shipped models and migrations both use; a factor model on another connection is
refused when the package boots. See [Storage](docs/guides/configuration.md#storage).

## Identity Model

Implement `MultiFactorAuthenticatable` on the identity the authentication stack hands back, and use `HasFactors`:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

class AppUser extends User implements MultiFactorAuthenticatable
{
    use HasFactors;
}
```

The trait gives the identity its factors (of the configured factor model), counts it as enabled once it has a
confirmed factor, treats it as an active person who requires nothing of their own sign-ins until the model says
otherwise, and deletes everything the package holds for it once the model is deleted (a soft delete keeps it). See
[Identity models](docs/guides/identity-models.md). What the current sign-in has proved lives separately, in the proof
store (`Mfa::proofs()`), so keep the two predicates orthogonal.

## Usage

The `Mfa` facade is the primary surface. Each method hands its call to the service of its capability:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

Mfa::requirement();                     // Requirement the current sign-in must meet
Mfa::isFresh('mfa.remove_factor');      // bool: fresh enough for the operation
Mfa::proofs();                          // list<Proof> of the current sign-in
Mfa::factors();                         // list<FactorSummary>, every factor, the preferred first
Mfa::factor($factorId);                 // ?FactorSummary
Mfa::offeredFactors();                  // list<FactorSummary>, the preferred first

Mfa::sendCode($factorId);               // SendResult: the challenge's id, or why none was sent
Mfa::requestAssertion($factorId);       // AssertionRequest: a passkey's options, or why there are none

Mfa::verify(Submission::factor($factorId, $code));                  // TOTP, or a driver of your own
Mfa::verify(Submission::challenge($factorId, $challengeId, $code)); // an email or SMS code
Mfa::verify(Submission::recoveryCode($code));                       // one attempt against the whole unused set
Mfa::verify(Submission::assertion($factorId, $response));           // a passkey

Mfa::startEnrollment($request);         // a pending factor, its grant and, by type, secrets or a first code
Mfa::confirmEnrollment($grant, $code);  // the factor, and recovery codes with the first one
Mfa::resendEnrollmentCode($grant);      // the code again, renewing nothing
Mfa::cancelEnrollment($grant);          // the pending factor gone
Mfa::renameFactor($factorId, $label);   // no step-up
Mfa::setPreferredFactor($factorId);     // offered first; no step-up
Mfa::removeFactor($factorId);           // FactorRemovalResult, on a fresh session; the last takes the recovery codes
Mfa::resetIdentity($user, $actor, $reason); // everything gone, every session revoked, re-enrolment obliged
Mfa::unlockFactor($user, $factorId, $actor); // bool: a live temporary lockout was lifted
Mfa::unlockIdentity($user, $actor);     // bool: a live temporary lockout was lifted
Mfa::forgetIdentity($user);             // everything held for a deleted identity; `HasFactors` does it for a model
Mfa::prune();                           // PruneResult; `mfa:prune` is the same from the console
Mfa::generateRecoveryCodes();           // RecoveryCodeGeneration: the codes, once, or why not
Mfa::recoveryCodeStatus();              // RecoveryCodeStatus|null: remaining, generation, generatedAt
```

Every flow is one call: [Helpers](docs/guides/helpers.md) lists what each returns, who it serves and which pending
action it needs, and how a route binds a factor, which it finds only within the caller's identity.

`Mfa::verify()` answers with a `VerificationResult`: the proof and the evaluation of the whole requirement with it, or a
machine-readable failure reason. Factors are looked up by id within the identity the request serves, so an id that does
not exist and one that belongs to someone else get the same answer, closing the "look up factor by ID from request
input" cross-account-bypass shape. See [Verification](docs/guides/verification.md).

### Middleware enforcement

The `mfa` middleware lets a request on only when the session it serves meets its whole requirement, read from the proofs
it holds. The alias is registered automatically; `mfa.exempt` marks the routes that complete a verification:

```php
Route::middleware('mfa')->group(function () {
    Route::get('/dashboard', DashboardController::class);
});

Route::middleware('mfa.exempt')->post('/mfa/verify', MfaVerifyController::class);
```

A route may ask for more, a level or a named operation's freshness:

```php
Route::middleware('mfa:level=aal2')->get('/billing', BillingController::class);
Route::middleware('mfa:operation=account.delete')->delete('/account', AccountController::class);
```

Bare `mfa` enforces the composed requirement and adds nothing, so on `never`, or `enrolled` with no factor, it asks
nothing further. It always refuses a guest, an identity that is not MFA-capable, a machine, an inactive identity and a
pending session, so a route machines use does not carry it. A refusal is an `InsufficientAuthenticationException`, a 401
carrying the requirement and masked factor summaries:

```php
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;

$this->renderable(function (InsufficientAuthenticationException $e) {
    return response()->json($e->toArray(), 401, ['WWW-Authenticate' => $e->wwwAuthenticate()]);
});
```

See [Route middleware](docs/guides/middleware.md).

### TOTP enrolment

Start the enrolment, which makes a pending factor and returns its secret, provisioning URI and grant once, as
`RevealedSecret` values for a response no cache keeps. Render the URI as a QR code, then confirm with the first code the
person's authenticator app shows:

```php
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;

$start = Mfa::startEnrollment(EnrollmentRequest::totp($user->email, label: 'Authenticator app'));

if (! $start->hasStarted()) {
    return response()->json(['reason' => $start->reason->value], 422);
}

return SecretResponse::json([
    'grant'            => $start->grant,
    'secret'           => $start->secret,
    'provisioning_uri' => $start->provisioningUri,
]);

// Then, with what the person sends back. Its time step is recorded, so the same
// code cannot be used again.
$confirmation = Mfa::confirmEnrollment($request->string('grant'), $request->string('code'));

return SecretResponse::json(['recovery_codes' => $confirmation->recoveryCodes]);
```

A start needs a fresh step-up, or for the first factor the first factor proved again, or the bootstrap path on a pending
sign-in. The grant lives no longer than that authority. See [Enrolment](docs/guides/enrollment.md).

The package computes TOTP codes itself (RFC 6238) and needs no other dependency. Each code is checked against the
application's `totp_window` steps either side of now (`mfa.totp.window` when it sets none), and each time step is
accepted once per factor, also when two requests race with the same code. See
[Configuration](docs/guides/configuration.md#totp) and [the TOTP design note](docs/design/totp.md).

### Recovery codes

Recovery codes are a fallback for lost factors, not a factor. An application accepts them once its block enables them
(`'recovery_codes' => ['enabled' => true]`), and only an identity with a confirmed factor can have a set.
`Mfa::generateRecoveryCodes()` replaces any earlier set atomically, keeps only a salted hash of each code, and answers
with the codes **exactly once**, as `RevealedSecret` values for a response no cache keeps, or with the reason it
refused:

```php
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;

$generation = Mfa::generateRecoveryCodes();

return $generation->wasGenerated()
    ? SecretResponse::json(['recovery_codes' => $generation->codes])
    : response()->json(['reason' => $generation->reason->value], 403);
```

Generating a set needs a session fresh enough for `mfa.generate_recovery_codes` that reaches the level the application
sets for issuing them. `Mfa::verify(Submission::recoveryCode($code))` ignores case, spaces and hyphens, checks the code
against every unused code of the set as one attempt, uses it up and makes a recovery code proof. See
[Recovery codes](docs/guides/recovery-codes.md).

### SMS and email senders

The email and SMS drivers deliver their codes through senders the application binds: `SmsSender` for SMS and
`EmailSender` for email. The shipped defaults throw `SenderNotConfiguredException`, and the configuration check refuses
an application that enables `sms` or `email` while its default is still bound, so a missing binding fails loudly before
anyone is sent a code. A sender's failure surfaces as `CodeDeliveryFailedException`, scrubbed of the code and the full
destination, with the sender's own exception as its previous one. Email can go through Laravel's mailer with the
package's own sender:

```php
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

$this->app->bind(EmailSender::class, MailEmailSender::class);
```

An SMS sender wraps the application's provider:

```php
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use Twilio\Rest\Client;

final readonly class TwilioSmsSender implements SmsSender
{
    public function __construct(
        private Client $twilio,
        private string $fromNumber,
    ) {}

    public function send(string $phoneNumber, #[\SensitiveParameter] string $message): void
    {
        $this->twilio->messages->create($phoneNumber, [
            'from' => $this->fromNumber,
            'body' => $message,
        ]);
    }
}
```

Bind it in a service provider:

```php
$this->app->bind(SmsSender::class, static fn ($app): TwilioSmsSender => new TwilioSmsSender(
    twilio: new Client(config('services.twilio.sid'), config('services.twilio.token')),
    fromNumber: config('services.twilio.from'),
));
```

The contracts expose only the destination and the message: the package owns drawing, hashing, binding and checking the
code, the resend cooldown, the delivery caps and lockouts, so the adapter stays thin. Sending for a factor answers a
`Codes\SendResult`: sent, with the challenge's id and expiry, or refused with `sending_capped` and the seconds to wait.
In tests, `Testing\FakeSmsSender::fake()` and `Testing\FakeEmailSender::fake()` capture the messages instead.

### Custom factor drivers

```php
Mfa::extend('webauthn', fn ($app) => new WebAuthnDriver(/* ... */));
```

Custom drivers must implement `SineMacula\Laravel\Mfa\Contracts\FactorDriver`, which also states the type's channel
kind and `amr` values (see [Factor drivers](docs/guides/extending.md#factor-drivers)). The manager builds a driver on
every call rather than caching it, so a driver keeps no state between calls, and the most recent registration is the one
used. Register it in a service provider's `register()` or `boot()` rather than mid-request, as a closure registered from
inside a request stays on the shared manager.

## Security Model

### Rate limiting

The package counts failures per factor, per identity and per IP address and locks each out past its cap (see
[Attempts and lockouts](docs/guides/attempts.md)). Those caps bound guessing at a factor; they do not bound load on the
endpoint itself. Layer Laravel's built-in `RateLimiter` on the verify endpoint as well:

```php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

RateLimiter::for('mfa-verify', static function (Request $request): array {
    $identifier = optional($request->user())->getAuthIdentifier() ?? $request->ip();

    return [
        Limit::perMinute(10)->by($request->ip() ?? 'unknown'),
        Limit::perMinute(5)->by((string) ($identifier ?: 'unknown')),
    ];
});

Route::post('/mfa/verify', VerifyController::class)
    ->middleware(['mfa.exempt', 'throttle:mfa-verify']);
```

Apply the throttle **only** to the verify endpoint — state-read routes (`Mfa::requirement()`, `Mfa::factors()`,
etc.) are called on every request and would exhaust the bucket without representing an attack signal.

### Proof store

Each verification on a signed-in session records a proof, kept by the default `SessionProofStore` in the Laravel session
for the identity's current sign-in on the application. Laravel's `Login` event begins a sign-in on the guard's
application and `Logout` or `CurrentDeviceLogout` ends it, so a new identity on a reused session inherits nothing. A
guard that fires neither event calls `Proofs\GuardHooks::signedIn()` and `signedOut()` instead; one that does neither
leaves no proof to rely on. A stateless guard rebinds `Contracts\ProofStore`.
See [Recorded proofs](docs/guides/proofs.md).

## Extensibility

All concrete classes in this package are `final` unless explicitly designed for extension. Extension is through
**composition and DI**, not inheritance:

| Extension point            | How                                                            |
|----------------------------|----------------------------------------------------------------|
| Custom factor driver       | Implement `FactorDriver`, register via `Mfa::extend()`         |
| Custom identity model      | Implement `MultiFactorAuthenticatable` and use `HasFactors`    |
| Requirements and freshness | Implement `RequirementPolicy` or `FreshnessGate` and bind it   |
| Custom proof store         | Implement `ProofStore` and bind it via the container           |
| Custom factor model        | Set `config('mfa.factor.model')` to your subclass              |
| Custom recovery code model | Set `config('mfa.recovery_codes.model')` to your subclass      |
| Event context              | Implement `EventContextResolver` and bind it via the container |
| SMS delivery               | Implement `SmsSender` and bind it via the container            |
| Email delivery             | Bind `MailEmailSender`, or your own `EmailSender`              |

Running it under Octane or in a queue worker, with read replicas, and what a database failure does: see
[Operations](docs/guides/operations.md).

The security and lifecycle contracts behind the package, for maintainers and reviewers, are in
[docs/design](docs/design/README.md).

## Requirements

- PHP ^8.3 (extensions: mbstring)
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer bench              # PHPBench hot-path benchmarks
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
