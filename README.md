# Laravel MFA

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-mfa.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)
[![Build Status](https://github.com/sinemacula/laravel-mfa/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-mfa/actions/workflows/tests.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-mfa/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-mfa)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-mfa/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-mfa)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-mfa.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)

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
  `MfaFactorDisabled` dispatched by the manager, not by consumer code.
- **Polymorphic identity support**: works with any Eloquent identity type (`User`, `Admin`, ...) via the
  shipped `authenticatable_type` / `authenticatable_id` morph.
- **Encrypted at rest**: factor `secret` and `code` columns are `encrypted`-cast; backup codes hash to SHA-256
  before persistence.
- **Per-factor lockouts**: configurable `max_attempts` + `lockout_minutes` for OTP drivers.
- **Zero ecosystem coupling**: depends only on Laravel and the standard `Authenticatable` contract.

## Design Notes

Adoption-focused quick-starts are below. Maintainer-oriented security and lifecycle contracts live in
`docs/design/`:

- `docs/design/verification-lifecycle-and-events.md`
- `docs/design/backup-code-consumption.md`
- `docs/design/attempts-and-lockout.md`
- `docs/design/per-device-verification-and-step-up.md`
- `docs/design/factor-payload-hygiene.md`

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

For TOTP support, install the suggested dependency:

```bash
composer require pragmarx/google2fa
```

The TOTP driver checks for this package at runtime and raises a clear error if it is missing.

## Configuration

The published `mfa.php` config controls global expiry, lockout, and per-driver settings:

```php
return [
    'default_expiry'  => 20160, // minutes (14 days)
    'lockout_minutes' => 15,

    'drivers' => [
        'totp' => [
            'window' => 1,
        ],
        'email' => [
            'code_length'  => 6,
            'expiry'       => 10,
            'max_attempts' => 3,
        ],
        'sms' => [
            'code_length'      => 6,
            'expiry'           => 10,
            'max_attempts'     => 3,
            'message_template' => 'Your verification code is: :code',
        ],
        'backup_code' => [
            'code_length' => 10,
            'code_count'  => 10,
        ],
    ],
];
```

> **APP_KEY rotation.** Factor secrets are encrypted at rest via Laravel's `encrypted` cast, so a key rotation
> must use `php artisan key:rotate` rather than simply swapping `APP_KEY` in `.env` — a naive swap leaves
> existing factor rows un-decryptable.

## Identity Model

Implement `MultiFactorAuthenticatable` on the identity the authentication stack hands back:

```php
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Facades\Mfa;

class AppUser extends User implements MultiFactorAuthenticatable
{
    public function shouldUseMultiFactor(): bool
    {
        return true;
    }

    public function isMfaEnabled(): bool
    {
        return $this->authFactors()->exists();
    }

    public function authFactors(): Builder
    {
        return $this->factors()->getQuery();
    }

    public function factors(): MorphMany
    {
        // Resolves through `Mfa::factorModel()` so consumers swapping the
        // shipped model via `config('mfa.factor.model')` get their subclass
        // back without any further wiring.
        return $this->morphMany(Mfa::factorModel(), 'authenticatable');
    }
}
```

Canonical rule: `isMfaEnabled()` means "has at least one enrolled factor". Per-request verification freshness
lives separately on `Mfa::hasExpired()` / the verification store, so keep the two predicates orthogonal.

> **Consumed backup codes.** A spent backup-code row keeps its `Factor` record — only the `secret` is
> nulled — so an audit trail survives. If backup codes are the only factor type a user might hold, filter
> spent rows out of `isMfaEnabled()` so a user who has consumed every recovery code does not read as
> "enabled" despite holding no usable credential:
>
> ```php
> public function isMfaEnabled(): bool
> {
>     return $this->authFactors()
>         ->where(function ($query) {
>             $query->where('driver', '!=', 'backup_code')
>                 ->orWhereNotNull('secret');
>         })
>         ->exists();
> }
> ```

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
Mfa::enrol($factor);                    // MfaFactorEnrolled
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

An optional `max-age` parameter overrides `default_expiry` per route group — the step-up lever for sensitive
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

Generate a shared secret and a provisioning URI, render the URI as a QR code, then hand a fresh `Factor` to
`Mfa::enrol()`:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;

$driver = Mfa::driver('totp');
$secret = $driver->generateSecret();
$uri    = $driver->provisioningUri(
    issuer: config('app.name'),
    accountName: $user->email,
    secret: $secret,
);

// Render $uri as a QR code with your library of choice.

$factor         = new Factor;
$factor->driver = 'totp';
$factor->label  = 'Authenticator app';
$factor->secret = $secret;

// `Mfa::enrol()` stamps the identity's morph columns itself —
// callers do not (and should not) populate them.
Mfa::enrol($factor);
```

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

The contract exposes only the recipient and rendered message — the package owns code generation, template
substitution, lockouts, and verification state — so the adapter stays thin.

### Custom factor drivers

```php
Mfa::extend('webauthn', fn ($app) => new WebAuthnDriver(/* ... */));
```

Custom drivers must implement `SineMacula\Laravel\Mfa\Contracts\FactorDriver`. Register the driver **before**
any request code calls `Mfa::driver(...)`: Laravel's manager caches resolved drivers per request, so an
`extend()` call made after the driver is already resolved silently has no effect. Bind in a service
provider's `register()` / `boot()` rather than mid-request.

## Security Model

### Rate limiting

The per-factor lockout (`max_attempts` + `lockout_minutes`) protects an individual factor from runaway
attempts on the same code, but does not by itself defend against distributed brute force across many factors
or DoS against the lockout window. Layer Laravel's built-in `RateLimiter` on the verify endpoint:

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

| Extension point           | How                                                            |
|---------------------------|----------------------------------------------------------------|
| Custom factor driver      | Implement `FactorDriver`, register via `Mfa::extend()`         |
| Custom identity model     | Implement `MultiFactorAuthenticatable` on your Eloquent model  |
| Organisation enforcement  | Implement `MfaPolicy` and bind it via the container            |
| Custom verification store | Implement `MfaVerificationStore` and bind it via the container |
| Custom factor model       | Set `config('mfa.factor.model')` to your subclass              |
| Custom SMS gateway        | Implement `SmsGateway` and bind it via the container           |

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
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
