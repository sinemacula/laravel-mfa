# Installation

```bash
composer require sinemacula/laravel-mfa
```

The package registers itself, and needs PHP ^8.3 with `mbstring` and Laravel ^12.40 or ^13.3. Every class name below is
relative to `SineMacula\Laravel\Mfa`.

## Publishing and migrating

Publish the config and the migrations, then migrate:

```bash
php artisan vendor:publish --tag=mfa-config
php artisan vendor:publish --tag=mfa-migrations
php artisan migrate
```

The migrations create seven tables, on the storage connection: `mfa_factors`, `mfa_identity_states`, `mfa_enrollments`,
`mfa_codes`, `mfa_recovery_codes`, `mfa_attempts` and `mfa_passkey_associations`. Each name is configurable, so set any
you want to change first (see [Table names and models](configuration.md#table-names-and-models)), and choose the
connection with `storage.connection` (see [Storage](configuration.md#storage)).

A migration refuses to run over an existing table of the same name, before changing anything, with an
`Exceptions\TableAlreadyExistsException` naming the configuration key that renames its table. Run the migrations with
your migration user: at run time the package needs only `SELECT`, `INSERT`, `UPDATE` and `DELETE`, and it changes no
schema.

`php artisan vendor:publish --tag=mfa-lang` publishes the English messages, which you need only to start a translation
from (see [Localisation](localization.md)).

## The first application

An application is the app being signed into, by default the name of the guard that authenticated the request. It enables
nothing until its block says so, and a name nobody configured enables nothing. Give it the types it accepts, when it
requires a factor and the first factor its guard signs people in with:

```php
'applications' => [
    'web' => [
        'types'          => ['totp', 'email'],
        'requirement'    => 'enrolled',
        'recovery_codes' => ['enabled' => true],
        'bootstrap'      => ['enabled' => false, 'types' => []],
        'first_factor'   => ['method' => 'password', 'channel' => 'password'],
    ],
],
```

`requirement` is `never`, `enrolled` (required once the identity has a confirmed factor, which is optional MFA) or
`always`. Without a `first_factor`, or a `Contracts\FirstFactorResolver` of your own, the package cannot tell which
factors are independent of the sign-in, so the configuration check fails. Every key is in
[Applications](configuration.md#applications).

Then give your identity model the contract and the trait (see [Identity models](identity-models.md)), and check the
result, which is worth doing from your deploy pipeline as well:

```bash
php artisan mfa:check
```

## Senders

The email and SMS drivers deliver their codes through senders you bind: `Contracts\SmsSender` for SMS and
`Contracts\EmailSender` for email. The shipped defaults throw `Exceptions\SenderNotConfiguredException`, and the
configuration check refuses an application that enables `sms` or `email` while its default is still bound, so a missing
binding fails loudly before anyone is sent a code. A sender's failure surfaces as
`Exceptions\CodeDeliveryFailedException`, scrubbed of the code and the full destination, with the sender's own exception
as its previous one.

Email can go through Laravel's mailer with the package's own sender:

```php
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

$this->app->bind(EmailSender::class, MailEmailSender::class);
```

An SMS sender wraps your provider, and writes the text itself, here in the package's own words:

```php
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use Twilio\Rest\Client;

final readonly class TwilioSmsSender implements SmsSender
{
    public function __construct(
        private Client $twilio,
        private string $fromNumber,
    ) {}

    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->twilio->messages->create($message->destination(), [
            'from' => $this->fromNumber,
            'body' => SmsCodeText::of($message),
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

A sender is given a `Codes\CodeMessage`: the code, its destination, its purpose, the application, its expiry and the
identity it is for, so it can word and lay out each message as the application wants. The package owns drawing,
hashing, binding and checking the code, the resend cooldown, the delivery caps and the lockouts, so a sender stays thin.
A sender that queues the message must encrypt the whole queued payload, and none may log the code (see
[Factor drivers](extending.md#factor-drivers)). Sending for a
factor answers a `Codes\SendResult`: sent, with the challenge's id and expiry, or refused with a failure reason, such as
`sending_capped`, and the seconds to wait when there are any (see [Sending a code](verification.md#sending-a-code)). In
tests, `Testing\FakeSmsSender::fake()` and `Testing\FakeEmailSender::fake()` keep the messages
instead (see [Testing](testing.md)).

The `passkey` type needs a `Contracts\PasskeyGateway` the same way, as this package stores no WebAuthn credentials and
runs no ceremonies (see [Passkeys](extending.md#passkeys)).

## Three ways of running

The package behaves the same in each, and changes only through what is bound in the container: it never looks for a
sibling, and references no class of one. How the three hold together is in
[the operating modes design note](../design/operating-modes.md).

### Alone

Behind any Laravel guard (session, Sanctum, Passport or your own) whose `Auth::user()` implements
`Contracts\MultiFactorAuthenticatable`:

- each sign-in's proofs live in the Laravel session, by the default `Proofs\SessionProofStore`, begun on Laravel's
  `Login` event and forgotten on `Logout` or `CurrentDeviceLogout`;
- a guard that fires neither event calls `Proofs\GuardHooks`, and a stateless one binds its own `Contracts\ProofStore`
  (see [Recorded proofs](proofs.md));
- there are no pending sessions, so a signed-in identity that still owes a factor is held at the gate: carry `mfa` on
  your routes and `mfa.exempt` on those that verify or enrol, so it can reach only those (see [Route
  middleware](middleware.md)). An active session steps up by default, so ask for `Purpose::SIGN_IN` on the verification
  that completes such a sign-in (see [The purpose](verification.md#the-purpose)).

### With `laravel-authentication`

The same model implements `Identity` from that package and `Contracts\MultiFactorAuthenticatable` from this one: both
extend Laravel's `Authenticatable`, so one class satisfies both. An adapter of yours implements this package's contracts
with that package's, and binds them in a service provider, so proofs live on the authentication session through a
rebound `Contracts\ProofStore`, a sign-in waits pending with `mfa` outstanding, and a step-up returns a new access
token. [Seams with an authentication layer](extending.md#seams-with-an-authentication-layer) names what each contract
meets and what a seam still needs from the layer, and warns against enabling `passkey` without it.

### Within `laravel-iam`

`sinemacula/laravel-iam` installs the suite and provides those adapters, with its own requirement seams and the audit
listeners, so you configure the applications and bind the senders. This package knows nothing of it.
