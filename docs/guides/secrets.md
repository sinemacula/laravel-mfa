# Secrets

Some of what the package hands back is secret: the TOTP secret and its provisioning URI when an enrolment starts, and
the recovery codes when a set is generated. Each is returned once, for the response that shows it, and the package keeps
no plaintext of it afterwards: a TOTP secret is stored encrypted, because the verifier needs it, and codes are stored
hashed. This page covers how those secrets reach the person and nothing else: the value they are returned in, the
response that sends them, the redaction that keeps them out of logs and traces, and the rotation of the key TOTP
secrets are encrypted with.

## Secrets shown once

A secret is returned as a `Secrets\RevealedSecret`. Its plaintext leaves it only through `reveal()`; every other way
out refuses:

| Use                                                                 | What happens                               |
|---------------------------------------------------------------------|--------------------------------------------|
| `reveal()`                                                          | The plaintext                              |
| Cast to a string, interpolated into one, or concatenated            | `Exceptions\SecretNotRevealedException`    |
| Encoded as JSON, `response()->json()` included                      | `Exceptions\SecretNotRevealedException`    |
| Serialised (a session, a cache, a queued job) or unserialised       | `Exceptions\SecretNotRevealedException`    |
| Dumped with `print_r`, `var_dump`, `var_export` or Laravel's dumper | A `[redacted]` marker, never the plaintext |
| Logged, in a log's context or Laravel's shared context              | `[redacted]`, as described below           |

Class names are relative to `SineMacula\Laravel\Mfa`. The exception is a `LogicException`: reaching for the plaintext
any other way is a bug in the calling code, so it fails loudly rather than send or keep the secret.

## Sending a secret

Send a secret with `Secrets\SecretResponse::json()`. It reveals every `RevealedSecret` in the data, at any depth, and
sends the response with `Cache-Control: no-store` and `Pragma: no-cache`, so neither the browser nor a proxy keeps it:

```php
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;

return SecretResponse::json([
    'secret'           => $secret,           // a RevealedSecret
    'provisioning_uri' => $provisioningUri,  // a RevealedSecret
    'recovery_codes'   => $recoveryCodes,    // a list of RevealedSecret
]);
```

`SecretResponse::withoutStoring($response)` sets the same headers on any response, replacing whatever caching it
allowed, for a route that builds its own.

Place the `mfa.no-store` middleware on the routes that start an enrolment or generate recovery codes. It sends every
response of those routes with the same headers, however the route builds them, so a secret a route reveals itself is
covered too:

```php
Route::post('/mfa/enrollments', StartEnrollmentController::class)->middleware(['auth', 'mfa.no-store']);
Route::post('/mfa/recovery-codes', GenerateRecoveryCodesController::class)->middleware(['auth', 'mfa.no-store']);
```

A stored secret is never returned again: to show a person a TOTP secret they lost, enrol a new factor.

## Logs and exceptions

While `secrets.redact` is on (it is by default, see [Secrets](configuration.md#secrets)), the package keeps secrets,
codes and full destinations out of the application's logs and error reports:

- **Log records.** When it boots, the package adds the `Secrets\RedactSecretsInLogs` tap to every channel in
  `logging.channels`. The tap pushes the `Secrets\RedactSecrets` Monolog processor onto the channel once, which runs
  after Laravel's shared context is added and before any handler writes the record. It redacts:
  - a `RevealedSecret` or a `\SensitiveParameterValue`, anywhere in the context or the extra data;
  - the value of any key naming a secret, a code or a destination: `secret`, `totp_secret`, `code`, `codes`, `otp`,
    `one_time_code`, `recovery_code`, `recovery_codes`, `destination`, `provisioning_uri` and `otpauth_uri`, compared
    without case, underscores, hyphens or spaces, so `recoveryCodes` counts, at any depth;
  - an `otpauth://` provisioning URI anywhere in the message or in a string value;
  - the arguments recorded in the trace of an exception in the context, as below.

  A masked destination, such as a `FactorSummary`'s, is kept. A channel added to the configuration after the package
  boots is not tapped: list `RedactSecretsInLogs::class` in its `tap`, or `RedactSecrets::class` in a `monolog`
  channel's `processors`. Listeners of Laravel's `MessageLogged` event, such as `Log::listen()` callbacks, are handed
  the context before any processor runs, so they see it unredacted.
- **Exception traces.** A trace records the arguments of every call unless PHP runs with
  `zend.exception_ignore_args` on, and its string form shows the start of each string, so a code passed down the
  stack would reach the log. The package registers a `report` callback on Laravel's exception handler that scrubs
  every reported exception and every previous one with `Secrets\TraceScrubber`: every argument of a call into one of
  the package's classes, or made from one of its files, becomes `[redacted]`, because a frame cannot say which of its
  arguments is a code; other frames keep their arguments, with the secrets in them redacted as in a log record. The
  context an exception's `context()` method gives is redacted as a log record's is.

An error reporter registered on the exception handler before the package booted, such as one added in
`bootstrap/app.php`, sees an exception before it is scrubbed. Scrub it first in the same place:

```php
use SineMacula\Laravel\Mfa\Secrets\TraceScrubber;

->withExceptions(function (Exceptions $exceptions) {
    $exceptions->report(fn (Throwable $e) => TraceScrubber::scrub($e));
    // the error reporter's own registration follows
})
```

or run PHP with `zend.exception_ignore_args` on, as PHP's production configuration does, so no trace records
arguments at all.

Events never carry a secret, a code or a full destination (see [Events](events.md#what-events-never-carry)), and the
package's own exceptions carry factor summaries, never factors.

Set `MFA_SECRETS_REDACT=false` only when the application redacts its logs and error reports itself.

## Rotating the application key

TOTP secrets are encrypted with Laravel's encrypter, under `APP_KEY`. To rotate the key, set the new key as `APP_KEY`
and list the old one in `APP_PREVIOUS_KEYS` (several, comma-separated):

```dotenv
APP_KEY=base64:new...
APP_PREVIOUS_KEYS=base64:old...
```

Laravel decrypts with the current key and then each previous key in turn, so every factor enrolled under the old key
keeps verifying. The package does not encrypt a stored secret again under the new key when it reads it, so keep the
old key listed for as long as any factor enrolled before the rotation exists. A key dropped from both leaves those
factors' secrets undecryptable: they fail to verify with an error, and the people who hold them need another factor or
a reset.
