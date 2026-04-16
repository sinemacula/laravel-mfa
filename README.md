# Laravel MFA

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-mfa.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)
[![Build Status](https://github.com/sinemacula/laravel-mfa/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-mfa/actions/workflows/tests.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-mfa/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-mfa)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-mfa/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-mfa)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-mfa.svg)](https://packagist.org/packages/sinemacula/laravel-mfa)

Driver-based multi-factor authentication for Laravel. Supports **TOTP**, **email codes**, **SMS codes**, and **backup
codes** out of the box, with a pluggable driver API for custom factor types.

Works with any authentication stack - SessionGuard, Sanctum, Passport, custom guards, or
`sinemacula/laravel-authentication`. No coupling, no opinions about your auth layer. Attach middleware to enforce MFA on
any route; catch structured exceptions to render whatever UI your app needs.

## Features

- **Four built-in factor drivers**: TOTP, email code, SMS code, backup codes - register via the MFA manager
- **Pluggable driver API**: register custom factor drivers through the Laravel-style `extend()` method
- **Route enforcement middleware**: single middleware to require MFA verification on any route or route group
- **Route skip mechanism**: mark verification endpoints as exempt to prevent enforcement loops
- **Structured exceptions**: `MfaRequiredException` and `MfaExpiredException` carry the user's available factors
- **MFA state inspection**: query whether the current user has MFA set up, should use MFA, or has an expired
  verification
- **Polymorphic identity support**: works with any Eloquent identity type (User, Admin, etc.) via polymorphic
  association
- **Constant-time verification**: all built-in drivers use `hash_equals()` for timing-attack resistance
- **Configurable everything**: per-driver code length, expiry, max attempts, and global verification expiry
- **Zero ecosystem coupling**: depends only on Laravel and the standard `Authenticatable` contract

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

The published `mfa.php` config controls global expiry and per-driver settings:

```php
return [
    'default_expiry' => 20160, // minutes (14 days)

    'drivers' => [
        'totp' => [
            'window' => 1,
        ],
        'email' => [
            'code_length'  => 6,
            'expiry'       => 10,  // minutes
            'max_attempts' => 3,
        ],
        'sms' => [
            'code_length'  => 6,
            'expiry'       => 10,
            'max_attempts' => 3,
        ],
    ],
];
```

## Usage

### Middleware enforcement

Apply `RequireMfa` to routes that need MFA protection:

```php
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Middleware\SkipMfa;

Route::middleware([RequireMfa::class])->group(function () {
    Route::get('/dashboard', DashboardController::class);
    Route::get('/settings', SettingsController::class);
});

// Exempt the verification endpoints themselves
Route::middleware([SkipMfa::class])->group(function () {
    Route::post('/mfa/verify', MfaVerifyController::class);
});
```

### Step-up authentication

The `mfa` middleware accepts an optional `max-age` minutes parameter to override the global `default_expiry`
on a per-route basis. Use it to gate sensitive actions behind a recent verification without forcing the global
expiry to be aggressive:

```php
// Standard MFA gate (uses default_expiry from config)
Route::middleware('mfa')->group(function () {
    Route::get('/dashboard', DashboardController::class);
});

// Step-up gate: require verification within the last 5 minutes
Route::middleware('mfa:5')->delete('/account', AccountController::class);

// Strict every-request gate for the highest-risk actions
Route::middleware('mfa:0')->post('/api/admin/delete-everything', NukeController::class);
```

`mfa:0` rejects every request — it requires the user to step through verification immediately before the
action — so reserve it for actions that justify the friction.

When MFA is required but not verified, `MfaRequiredException` is thrown. When a previous verification has expired,
`MfaExpiredException` is thrown. Both carry the user's available factors:

```php
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;

// In your exception handler
$this->renderable(function (MfaRequiredException $e) {
    return response()->json([
        'message' => $e->getMessage(),
        'factors' => $e->getFactors(),
    ], 401);
});
```

### MFA state inspection

Use the `Mfa` facade to query the current user's MFA state:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

Mfa::shouldUse();       // bool - should the current user complete MFA?
Mfa::isSetup();         // bool - has the user set up at least one factor?
Mfa::hasExpired();      // bool - has the current verification expired?
Mfa::getFactors();      // Collection|null - the user's registered factors
```

### Verifying a code

Resolve a driver through the manager and verify:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

$driver = Mfa::driver('totp');
$valid  = $driver->verify($code, $factor);
```

### TOTP enrolment

Generate a shared secret and a provisioning URI, render the URI as a QR code with the QR-rendering library
of your choice, then persist the secret on a `Factor` row:

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

// Render $uri as a QR code with your library of choice. With endroid/qr-code:
//   $qr = Builder::create()->writer(new PngWriter)->data($uri)->build();

Factor::create([
    'authenticatable_type' => $user::class,
    'authenticatable_id'   => $user->getKey(),
    'driver'               => 'totp',
    'label'                => 'Authenticator app',
    'secret'               => $secret,
]);
```

### Custom factor drivers

Register a custom driver via the `extend()` API:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

Mfa::extend('webauthn', function ($app) {
    return new WebAuthnDriver(/* ... */);
});
```

Custom drivers must implement `SineMacula\Laravel\Mfa\Contracts\FactorDriver`.

### Identity model setup

Your identity model implements `MultiFactorAuthenticatable`:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

class AppUser extends User implements MultiFactorAuthenticatable
{
    public function shouldUseMultiFactor(): bool
    {
        return true;
    }

    public function isMfaEnabled(): bool
    {
        return $this->authFactors()->where('verified', true)->exists();
    }

    public function authFactors(): \Illuminate\Contracts\Database\Eloquent\Builder
    {
        return $this->morphMany(AuthFactor::class, 'authenticatable');
    }
}
```

## Extensibility

All concrete classes in this package are `final` unless explicitly designed for extension. Extension is through
**composition and DI**, not inheritance:

| Extension point          | How                                                                    |
|--------------------------|------------------------------------------------------------------------|
| Custom factor driver     | Implement `FactorDriver`, register via `Mfa::extend()`                 |
| Custom identity model    | Implement `MultiFactorAuthenticatable` on your Eloquent model          |
| Organisation enforcement | Implement `EnforcesMfa` on your organisation model                     |
| Custom factor model      | Swap via configuration (publishable migrations)                        |

## Requirements

- PHP ^8.3 (extensions: mbstring)
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test
composer test:coverage
composer check
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
for guidelines on branching, commits, code quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly.
See [SECURITY.md](SECURITY.md) for the disclosure policy and contact
details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
