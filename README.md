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

Driver-based multi-factor authentication for Laravel. Adds factors (TOTP, email codes, SMS codes and passkeys),
recovery codes, step-up verification and a route gate to any guard, and says what a session's proofs add up to on the
scale NIST SP 800-63B-4 defines.

Works alone behind any Laravel guard and any `Authenticatable` model, or with `sinemacula/laravel-authentication`
through adapters you or `sinemacula/laravel-iam` bind: this package references no class of another. Routes, controllers
and user interfaces stay yours.

## Core Concept

| Concept             | What it is                                                                                                           |
|---------------------|----------------------------------------------------------------------------------------------------------------------|
| **Factor**          | One enrolled means of proving a further factor: an authenticator app, a phone, an email address or a passkey.        |
| **Proof**           | One verified authentication event on a session, with its time, its binding and the properties actually observed.     |
| **Requirement**     | What a session must prove: an additional verification, multifactor authentication, a level, phishing resistance.     |
| **Application**     | The app being signed into, by default the guard's name. It chooses the types it accepts, its requirement and limits. |
| **Recovery code**   | One code of a single-use set for a person who has lost their factors. A fallback, never a factor.                    |
| **Assurance level** | What a combination of proofs supports: `aal1`, `aal2`, `aal3`, or `unclassified` when the evidence supports none.    |

Factors belong to the identity and are the same in every application; proofs belong to one sign-in. Everything the
package decides about a session is worked out from its proofs, never from a single "verified at" time.

## Installation

```bash
composer require sinemacula/laravel-mfa
```

## Configuration

Publish the config and the migrations, then migrate:

```bash
php artisan vendor:publish --tag=mfa-config
php artisan vendor:publish --tag=mfa-migrations
php artisan migrate
```

An application enables nothing until it says so. Give each one a block in `config/mfa.php`, under the name of its guard,
naming the factor types it accepts, when it requires a factor and the first factor its guard signs people in with:

```php
'applications' => [
    'web' => [
        'types'          => ['totp', 'email'],
        'requirement'    => 'enrolled',
        'recovery_codes' => ['enabled' => true],
        'first_factor'   => ['method' => 'password', 'channel' => 'password'],
    ],
],
```

An application that enables `email` or `sms` binds a sender to deliver its codes:

```php
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

$this->app->bind(EmailSender::class, MailEmailSender::class);
```

Every setting has a production-safe default and enforced bounds. The package checks the whole configuration when it
boots, and `php artisan mfa:check` reports every problem for a deploy pipeline. TOTP secrets are encrypted with
`APP_KEY`, so keep an old key in `APP_PREVIOUS_KEYS` when you rotate it (see
[Rotating the application key](docs/guides/secrets.md#rotating-the-application-key)), and every package table lives on
one connection, `storage.connection` (see [Storage](docs/guides/configuration.md#storage)).

See [Installation](docs/guides/installation.md) for senders and the ways of running, and
[Configuration](docs/guides/configuration.md) for every option.

## Usage

Give your identity model the contract and the trait:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

class AppUser extends User implements MultiFactorAuthenticatable
{
    use HasFactors;
}
```

Verify on routes of your own, through the `Mfa` facade:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;

Route::middleware(['web', 'auth', 'mfa.exempt'])->post('/mfa/verify', function (Request $request) {
    $result = Mfa::verify(CallerContext::fromRequest($request), Submission::factor(
        $request->string('factor')->toString(),
        $request->string('code')->toString(),
    ), Purpose::SIGN_IN);

    return $result->isFailed()
        ? response()->json(['reason' => $result->reason->value], 422)
        : response()->noContent();
});
```

Every helper that acts for a person takes the caller first, read from the request once with
`CallerContext::fromRequest()` or built from plain values away from one (see
[The caller](docs/guides/helpers.md#the-caller)). This form is for TOTP. Email and SMS factors use `Mfa::sendCode()` and
then `Submission::challenge()`, and a step-up leaves the purpose out (see
[Verification](docs/guides/verification.md#sending-a-code)).

Gate the rest with the middleware, asking for more where a route needs it:

```php
Route::middleware('mfa')->group(function () {
    Route::get('/dashboard', DashboardController::class);

    Route::middleware('mfa:level=aal2')->get('/billing', BillingController::class);
    Route::middleware('mfa:operation=account.delete')->delete('/account', DeleteAccountController::class);
});
```

A request that falls short raises `InsufficientAuthenticationException`, a `401` carrying the requirement and the
factors on offer as masked summaries (see [Route middleware](docs/guides/middleware.md#answering)).

Before you ship, read [CSRF protection](docs/guides/middleware.md#csrf-protection) for cookie-authenticated routes that
change factors or recovery codes, [Identity models](docs/guides/identity-models.md) for machines and inactive
identities, and [Secrets](docs/guides/secrets.md) for sending what is shown once. To claim an assurance level, follow
the [NIST SP 800-63B-4 compliance profile](docs/guides/compliance.md).

### Guides

| Guide                                                          | Covers                                                                                         |
|----------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| [Installation](docs/guides/installation.md)                    | Publishing, the first application, senders, and running alone or with the suite                |
| [Identity models](docs/guides/identity-models.md)              | The contract and trait, machines, inactive identities, deleting an identity                    |
| [Configuration](docs/guides/configuration.md)                  | Every key, its default and its bounds, storage, and the configuration check                    |
| [Helpers](docs/guides/helpers.md)                              | Every `Mfa::` helper, who it serves, how it refuses, and binding a factor to a route           |
| [Enrolment](docs/guides/enrollment.md)                         | Starting and confirming a factor, the grant, replacing a factor, labels                        |
| [Verification](docs/guides/verification.md)                    | `Mfa::verify()`, what a code is bound to, offers, results, failure reasons, completion         |
| [Recovery codes](docs/guides/recovery-codes.md)                | Generating, redeeming and removing a set, and what it costs                                    |
| [Attempts and lockouts](docs/guides/attempts.md)               | Every counter, what resets it, the failure ceiling and limiting the endpoint                   |
| [Requirements and step-up](docs/guides/requirements.md)        | What a sign-in must prove, per-operation freshness, and the contracts behind them              |
| [Route middleware](docs/guides/middleware.md)                  | `mfa` and `mfa.exempt`, who is refused, answering, CSRF protection, the authentication context |
| [Recorded proofs](docs/guides/proofs.md)                       | Reading proofs, sign-ins, custom and stateless guards, invalidating proofs                     |
| [Proofs, assurance and requirements](docs/guides/assurance.md) | The values, the combination policy, the default classification and the stable names            |
| [Compliance](docs/guides/compliance.md)                        | What an application must also configure to claim a NIST SP 800-63B-4 level                     |
| [Factor lifecycle](docs/guides/lifecycle.md)                   | Listing, removing, resetting, unlocking and pruning                                            |
| [Secrets](docs/guides/secrets.md)                              | What is shown once, sending it, redaction, failed queries and key rotation                     |
| [Events](docs/guides/events.md)                                | Every event, its payload and its context                                                       |
| [Localisation](docs/guides/localization.md)                    | Every message, translating it, and what is not translated                                      |
| [Operations](docs/guides/operations.md)                        | Octane, queue workers, read replicas, database failure and the cache                           |
| [Testing](docs/guides/testing.md)                              | Fake senders, the current TOTP code, acting as a verified identity                             |
| [Extending](docs/guides/extending.md)                          | Custom drivers and models, every seam and its default, the seams with an authentication layer  |

The security and lifecycle contracts behind them, for maintainers and reviewers, are in
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
