# Secrets

Some of what the package hands back is secret: the TOTP secret and its provisioning URI when an enrolment starts, and
the recovery codes when a set is generated. Each is meant for the response that shows it, and the package keeps no
plaintext of it afterwards: a TOTP secret is stored encrypted, because the verifier needs it, and codes are stored
hashed. This page covers how those secrets reach the person and nothing else: the value they are meant to be returned
in, the response that sends them, the redaction that keeps them, delivered codes and full destinations out of logs and
traces, and the rotation of the key TOTP secrets are encrypted with.

## Secrets shown once

`Secrets\RevealedSecret` is the type secrets are returned in, revealed explicitly, and only for the response to the
client and for storing the factor. `Mfa::generateRecoveryCodes()` answers with each recovery code as one (see
[Recovery codes](recovery-codes.md)), and `Mfa::startEnrollment()` returns the TOTP secret, the provisioning URI and
the enrolment grant as them (see [Enrolment](enrollment.md)), as the TOTP driver's `startEnrollment()` and
`provisioningUri()` do. Wrapping a secret of your own, `new RevealedSecret($secret)`, gives it the protection below.

A `RevealedSecret`'s plaintext leaves it only through `reveal()`; every other way out refuses:

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
  `logging.channels`, and applies it straight away to any channel the application resolved before then. The tap makes
  the `Secrets\RedactSecrets` Monolog processor the last processor the channel runs, after Laravel's shared context
  and the channel's own `processors`, so it sees everything they add, and before any handler writes the record. It
  redacts:
  - a `RevealedSecret` or a `\SensitiveParameterValue`, anywhere in the context or the extra data;
  - a code message, a `Codes\CodeMessage` handed to a sender, a `Codes\MfaCodeMessage` or a queued job sending one,
    which becomes `[redacted]`;
  - the value of any key naming a secret, a code or a destination: `secret`, `totp_secret`, `code`, `codes`, `otp`,
    `one_time_code`, `recovery_code`, `recovery_codes`, `destination`, `address`, `email`, `phone`, `phone_number`,
    `to`, `recipient`, `provisioning_uri`, `otpauth_uri`, `grant` and `enrollment_grant`, compared without case,
    underscores, hyphens or spaces, so `recoveryCodes` and `phoneNumber` count, at any depth;
  - an `otpauth://` provisioning URI anywhere in the message or in a string value;
  - in the message, and in the message of every exception in the context and of its previous ones, every sensitive
    value the context and the extra data hold: one marked as sensitive, one under a key above, in an object's logged
    form too, a code message's code and recipients' addresses, and what a logged exception recorded in its trace.
    Objects are turned into their logged form once, and the values are collected from that form before anything is
    redacted, so a message copied from an exception's before it was scrubbed, as
    `Log::error($e->getMessage(), ['exception' => $e])` copies it, loses them too, and a logged exception loses a
    code logged beside it even when PHP recorded no arguments. A code message's values are replaced wherever they
    appear; any other value only where the message is the value, or contains it and it is six characters or more;
  - the secrets held in an object, which is logged as what Monolog would make of it, keyed by its class: a
    collection's or model's array form, a `JsonSerializable`'s JSON form, a `Stringable`'s string, or a plain
    object's public properties, each redacted as above. An object that throws rather than give that form, as a value
    that refuses to be logged does on purpose, is logged as its class keyed to `[unserializable]`, so the log line is
    still written;
  - the message and the trace arguments of an exception in the context, as below.

  A masked destination, such as a `FactorSummary`'s, is kept. The walk stops ten levels deep and after the first
  thousand entries of an array, marking what it left out `[truncated]`, so a recursive context cannot exhaust memory.
  A channel added to the configuration after the package boots is not tapped: list `RedactSecretsInLogs::class` in
  its `tap`, or `RedactSecrets::class` last in a `monolog` channel's `processors`. Listeners of Laravel's
  `MessageLogged` event, such as `Log::listen()` callbacks, are handed the context before any processor runs, so they
  see it unredacted.
- **Exception traces and messages.** A trace records the arguments of every call unless PHP runs with
  `zend.exception_ignore_args` on, and its string form shows the start of each string, so a code passed down the
  stack would reach the log. The package registers a `report` callback on Laravel's exception handler that scrubs
  every reported exception and every previous one with `Secrets\ExceptionScrubber`:
  - every argument of a call into one of the package's classes, or made from one of its files, becomes `[redacted]`,
    because a frame cannot say which of its arguments is a code;
  - every string those calls received, every value any call marks with `#[\SensitiveParameter]`, and every value
    under a key above is redacted wherever it reappears in another frame: the facade's own frame, which records
    `Mfa::verify()` as `Facade::__callStatic('verify', [...])`, and the frames of the hasher, encrypter or
    driver the package hands it to. A string equal to one becomes `[redacted]`, and so does a string containing one of
    six characters or more;
  - a code message, or a queued job sending one, becomes `[redacted]` in every frame, nested in an argument too, and
    its code and recipients' addresses are redacted from any string containing them, whatever their length, such as
    the rendered body a mail transport received;
  - other arguments are kept, with the secrets in them redacted as in a log record;
  - the same values are redacted from the message of every exception in the chain, each occurrence replaced by
    `[redacted]`, and so is an `otpauth://` provisioning URI.

  The context an exception's `context()` method gives is redacted as a log record's is.
- **Delivery failures.** The package catches a sender's failure around the delivery alone, so the transaction still
  rolls back and the code is not kept. It knows the code and the factor's destination, so it scrubs both from the
  message and the trace of every exception in the failure's chain, on top of the above, whatever their length and
  whether or not PHP recorded any arguments, and throws `Exceptions\CodeDeliveryFailedException`, which names the
  factor's type and its masked destination, with the scrubbed failure as its previous exception.
  `MfaCodeMessage` does the same in its own `send()` with its code and recipients, so a queued message a queue worker
  fails to send is scrubbed before the worker reports it, where the package's code is no longer on the stack. The
  values are taken from each delivery and each message, never kept, so nothing collected for one job reaches the
  next. Both run whatever `secrets.redact` says. The senders' and drivers' parameters that carry a code, a message or
  a destination are marked `#[\SensitiveParameter]`, so PHP records none of them in a trace; mark your own sender's
  the same way.

An error reporter registered on the exception handler before the package booted, such as one added in
`bootstrap/app.php`, sees an exception before it is scrubbed. Scrub it first in the same place:

```php
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;

->withExceptions(function (Exceptions $exceptions) {
    $exceptions->report(fn (Throwable $e) => ExceptionScrubber::scrub($e));
    // the error reporter's own registration follows
})
```

or run PHP with `zend.exception_ignore_args` on, as PHP's production configuration does, so no trace records
arguments at all.

Events never carry a secret, a code or a full destination (see [Events](events.md#what-events-never-carry)), and the
package's own exceptions carry factor summaries, never factors.

Set `MFA_SECRETS_REDACT=false` only when the application redacts its logs and error reports itself.

## Failed queries

Laravel writes a query's bindings into a `QueryException`'s message and keeps them on the exception, and a driver's own
message can quote a stored value, so a failed write could carry a destination or a credential id in plaintext.
`Secrets\QueryExceptionMask` takes them out in place, keeping the class and the code, so a
`UniqueConstraintViolationException` is still caught as one:

- the message becomes the SQLSTATE, the driver error number, the connection's name and the SQL with placeholders;
- every previous exception's message becomes the SQLSTATE and the driver error number alone: no value is searched for
  and cut out, which an escaped or truncated copy would survive;
- the bindings are emptied, `errorInfo` keeps its SQLSTATE and number and loses the driver's text;
- the arguments its trace recorded are scrubbed as above, with the bindings among the values known;
- a `DeadlockException` above it, which is how Laravel raises a concurrency failure inside a nested transaction, loses
  the message it copied, keeping the words Laravel recognises it by and the query's summary.

This applies whatever `mfa.secrets.redact` says, where a failure leaves the package: a transaction it opened, a factor's
`persist()`, and `Database\WriteConnection::during()`, which route binding runs in. While redaction is on, the report
path masks too, for any chain whose SQL names one of the package's tables.

Its limits:

- A literal an application writes into its own raw SQL stays in the SQL. The queries the package builds bind every
  value.
- The plain reads a failure can come from outside those three places bind only hashes and owner keys. That holds because
  of what they are, not because of the mask: `tests/Integration/Database/QueryFailureSweepTest.php` keeps it true.
- Laravel's own retry in a transaction of yours, `DB::transaction($callback, $attempts)`, recognises a failure by
  SQLSTATE `40001` or by words in its message. A `DeadlockException` from a transaction the package opened inside yours
  keeps the words, so it is retried. A `QueryException` does not: of those only SQLSTATE `40001`, a MySQL deadlock, is
  still recognised. A PostgreSQL deadlock (`40P01`), a lock wait timeout and SQLite's locked database are recognised
  only by message, so retry those yourself, checking the SQLSTATE or the driver error number the exception keeps.

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
