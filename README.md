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

Driver-based multi-factor authentication for Laravel. Ships **TOTP**, **email codes**, **SMS codes**, and **backup
codes** out of the box, with a pluggable driver API for custom factor types.

Composes with any authentication stack — SessionGuard, Sanctum, Passport, a custom guard, or
`sinemacula/laravel-authentication`. No runtime coupling to the auth layer: depends only on Laravel's standard
`Authenticatable` contract. Attach middleware to enforce MFA on any route; catch structured exceptions to render
whatever UI you like.

## Features

- **Four built-in factor drivers**: TOTP, email code, SMS code, backup codes.
- **Pluggable driver API**: register custom factor drivers via the Laravel-style `Mfa::extend()` method.
- **Route enforcement middleware**: `mfa` gates a route, `mfa.skip` exempts the verification endpoints.
- **Step-up lever**: `mfa:N` overrides the global expiry per route group to require a recent verification for
  sensitive actions.
- **Structured exceptions**: `MfaRequiredException` and `MfaExpiredException` carry a masked `FactorSummary`
  list suitable for rendering a factor-picker UI.
- **Lifecycle events**: `MfaChallengeIssued`, `MfaVerified`, `MfaVerificationFailed`, `MfaFactorEnrolled`,
  `MfaFactorDisabled` dispatched by the manager, not by consumer code, and a catalogue of events for the enrolment,
  verification, recovery code and lifecycle flows, each carrying a scalar context and no secret, dispatched once its
  change commits (see [Events](docs/guides/events.md)).
- **Polymorphic identity support**: works with any Eloquent identity type (`User`, `Admin`, ...) via the
  shipped `authenticatable_type` / `authenticatable_id` morph.
- **Encrypted at rest**: factor `secret` and `code` columns are `encrypted`-cast; backup codes hash to SHA-256
  before persistence.
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
capability (`totp`, `codes`, `recovery_codes`, `attempts`, `enrollment`, `proofs`, `lifecycle`) for what is the same
everywhere:

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

    'proofs' => [
        'max_age_minutes' => 20160, // 14 days
    ],
];
```

Every setting has a production-safe default and enforced bounds. The package checks the whole configuration when it
boots, and `php artisan mfa:check` reports every problem for a deploy pipeline. Not every setting is applied yet: the
application blocks, among others, are checked but no flow reads them, so listing a type or a requirement there enforces
nothing for now. See [Configuration](docs/guides/configuration.md) for every key, its default, its bounds and whether it
is applied yet.

> **APP_KEY rotation.** Factor secrets are encrypted at rest via Laravel's `encrypted` cast, so a key rotation
> must use `php artisan key:rotate` rather than simply swapping `APP_KEY` in `.env` — a naive swap leaves
> existing factor rows un-decryptable.

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

    public function shouldUseMultiFactor(): bool
    {
        return true;
    }
}
```

The trait gives the identity its factors (of the configured factor model), counts it as enabled once it has a
confirmed factor, treats it as an active person who requires nothing of their own sign-ins until the model says
otherwise, and deletes everything the package holds for it once the model is deleted (a soft delete keeps it). See
[Identity models](docs/guides/identity-models.md). Per-request verification freshness lives separately on
`Mfa::hasExpired()` / the verification store, so keep the two predicates orthogonal.

## Usage

The `Mfa` facade is the primary surface. The manager orchestrates drivers, enforces factor ownership, handles
lockouts and attempt counting, and dispatches lifecycle events:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

Mfa::shouldUse();                       // bool
Mfa::isSetup();                         // bool
Mfa::hasEverVerified();                 // bool
Mfa::hasExpired();                      // bool
Mfa::getFactors();                      // Collection|null

Mfa::challenge($driver, $factor);       // MfaChallengeIssued
Mfa::verify($driver, $factor, $code);   // MfaVerified | MfaVerificationFailed
Mfa::enroll($factor);                   // MfaFactorEnrolled
Mfa::disable($factor);                  // MfaFactorDisabled
Mfa::issueBackupCodes();                // atomic rotation — returns plaintext once
```

Ownership is stamped by the package, never trusted from the caller — `verify()`, `challenge()`, and `disable()`
throw `FactorOwnershipMismatchException` when handed a factor owned by a different identity, closing the
"look up factor by ID from request input" cross-account-bypass shape.

### Middleware enforcement

The shipped `RequireMfa` middleware gates a route behind a valid MFA verification. The `mfa` alias is
registered automatically; `mfa.skip` exempts the verification endpoints themselves:

```php
Route::middleware('mfa')->group(function () {
    Route::get('/dashboard', DashboardController::class);
});

Route::middleware('mfa.skip')->post('/mfa/verify', MfaVerifyController::class);
```

An optional `max-age` parameter overrides `proofs.max_age_minutes` per route group — the step-up lever for sensitive
actions:

```php
Route::middleware('mfa:5')->delete('/account', AccountController::class);   // re-verify within 5 min
Route::middleware('mfa:0')->post('/admin/danger', DangerController::class); // every request
```

When MFA is required, `MfaRequiredException` is thrown; when a prior verification has expired,
`MfaExpiredException`. Both carry a masked `FactorSummary` list safe to ship through JSON bodies and log
sinks:

```php
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;

$this->renderable(function (MfaRequiredException $e) {
    return response()->json([
        'message' => $e->getMessage(),
        'factors' => $e->getFactors(),
    ], 401);
});
```

### TOTP enrolment

Start the enrolment on a fresh `Factor`, which stamps the TOTP parameters it will keep (`mfa.totp`'s algorithm,
digits and period) and returns a new secret. Store the secret on the factor, render its provisioning URI as a QR code,
confirm the first code the person's authenticator app shows, then hand the factor to `Mfa::enroll()`:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;

$factor        = new Factor;
$factor->type  = 'totp';
$factor->label = 'Authenticator app';

$driver         = Mfa::driver('totp');
$factor->secret = $driver->startEnrollment($factor);

$uri = $driver->provisioningUri(
    factor: $factor,
    issuer: config('app.name'),
    accountName: $user->email,
    secret: $factor->secret,
);

// Render $uri as a QR code with your library of choice, then check the
// first code the app shows. Its time step is recorded, so the same code
// cannot be used again. Enrol the factor only once the code is confirmed.
if (! $driver->confirm($factor, $request->string('code')->toString())) {
    return back()->withErrors(['code' => 'The code is not valid. Try the next one your app shows.']);
}

// `Mfa::enroll()` stamps the identity's morph columns itself —
// callers do not (and should not) populate them.
Mfa::enroll($factor);
```

The package computes TOTP codes itself (RFC 6238) and needs no other dependency. Each code is checked against the
application's `totp_window` steps either side of now (`mfa.totp.window` when it sets none), and each time step is
accepted once per factor, also when two requests race with the same code. See
[Configuration](docs/guides/configuration.md#totp) and [the TOTP design note](docs/design/totp.md).

### Backup codes

`Mfa::issueBackupCodes()` atomically replaces any prior batch (no overlap window where both old and new codes
would verify), persists each code as its own `Factor` row with the SHA-256 hash on `secret`, dispatches one
`MfaFactorEnrolled` event per code, and returns the plaintext set **exactly once**:

```php
$codes = Mfa::issueBackupCodes();

// Render `$codes` to the user — this is the only chance. Subsequent
// reads return the hashed `secret` column (not recoverable).
return view('mfa.backup-codes', ['codes' => $codes]);
```

Pass an explicit `$count` argument to override the configured default batch size for that single call:
`Mfa::issueBackupCodes(20)`.

### SMS gateway binding

The SMS driver delegates outbound delivery to a `SmsGateway` implementation. The shipped `NullSmsGateway`
throws `SmsGatewayNotConfiguredException` to surface missing wiring loudly — consumers enabling the SMS
driver bind their own implementation:

```php
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use Twilio\Rest\Client;

final readonly class TwilioSmsGateway implements SmsGateway
{
    public function __construct(
        private Client $twilio,
        private string $fromNumber,
    ) {}

    public function send(string $to, #[\SensitiveParameter] string $message): void
    {
        $this->twilio->messages->create($to, [
            'from' => $this->fromNumber,
            'body' => $message,
        ]);
    }
}
```

Bind it in a service provider:

```php
$this->app->singleton(SmsGateway::class, static fn ($app): TwilioSmsGateway => new TwilioSmsGateway(
    twilio: new Client(config('services.twilio.sid'), config('services.twilio.token')),
    fromNumber: config('services.twilio.from'),
));
```

The contract exposes only the destination and rendered message — the package owns code generation, template
substitution, lockouts, and verification state — so the adapter stays thin.

### Custom factor drivers

```php
Mfa::extend('webauthn', fn ($app) => new WebAuthnDriver(/* ... */));
```

Custom drivers must implement `SineMacula\Laravel\Mfa\Contracts\FactorDriver`, which also states the type's channel
kind and `amr` values (see [Factor drivers](docs/guides/extending.md#factor-drivers)). Register the driver **before**
any request code calls `Mfa::driver(...)`: Laravel's manager caches resolved drivers per request, so an
`extend()` call made after the driver is already resolved silently has no effect. Bind in a service
provider's `register()` / `boot()` rather than mid-request.

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
    ->middleware(['mfa.skip', 'throttle:mfa-verify']);
```

Apply the throttle **only** to the verify endpoint — state-read routes (`Mfa::shouldUse()`, `Mfa::isSetup()`,
etc.) are called on every request and would exhaust the bucket without representing an attack signal.

### Verification store

The default `SessionMfaVerificationStore` assumes consumers regenerate the session on auth state change —
Laravel's default on login / logout. Apps that disable session regeneration on login must call
`Mfa::forgetVerification()` themselves on auth state change, so a new identity cannot inherit the prior
identity's verification timestamp from a reused session.

## Extensibility

All concrete classes in this package are `final` unless explicitly designed for extension. Extension is through
**composition and DI**, not inheritance:

| Extension point            | How                                                            |
|----------------------------|----------------------------------------------------------------|
| Custom factor driver       | Implement `FactorDriver`, register via `Mfa::extend()`         |
| Custom identity model      | Implement `MultiFactorAuthenticatable` and use `HasFactors`    |
| Organisation enforcement   | Implement `MfaPolicy` and bind it via the container            |
| Custom verification store  | Implement `MfaVerificationStore` and bind it via the container |
| Custom factor model        | Set `config('mfa.factor.model')` to your subclass              |
| Custom recovery code model | Set `config('mfa.recovery_codes.model')` to your subclass      |
| Event context              | Implement `EventContextResolver` and bind it via the container |
| Custom SMS gateway         | Implement `SmsGateway` and bind it via the container           |

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
