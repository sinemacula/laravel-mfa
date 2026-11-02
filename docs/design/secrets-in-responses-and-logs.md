# Secrets in Responses and Logs

## Purpose

This note records how the secrets the package returns once (TOTP secrets, provisioning URIs and recovery codes) reach
the person and nothing else: the value they are meant to be returned in, the response that sends them without a cache
keeping it, the redaction that keeps them, delivered codes and full destinations out of logs, exception messages and
traces, and the key rotation TOTP secrets survive. It follows the rule `sinemacula/laravel-authentication` follows for
secrets in responses, so a middleware placed on a route covers any secret the route sends, whichever package returned
it.

## Invariants

- `Secrets\RevealedSecret` is the type secrets are returned in, revealed explicitly only for the response to the client
  and for storing the factor. `RecoveryCodes\RecoveryCodeService::generate()` returns each recovery code of a new set
  as one, and the enrolment flow returns the TOTP secret, the provisioning URI and the grant as them (see
  [Enrolment](enrollment.md)), from `TotpDriver::startEnrollment()` and `provisioningUri()` up.
- A `RevealedSecret` holds its plaintext as a `\SensitiveParameterValue`. The
  plaintext leaves it only through `reveal()`. `__toString()`, `jsonSerialize()`, `__serialize()` and
  `__unserialize()` throw `Exceptions\SecretNotRevealedException`, a `LogicException`; `__debugInfo()` gives a
  `[redacted]` marker, and the `\SensitiveParameterValue` gives `print_r`, `var_dump`, `var_export`, array casts and
  Symfony's VarDumper nothing. The class is final and readonly.
- A value that holds a secret but is not returned to show it keeps to the same standard: `Verification\Submission`'s
  code and response, `Verification\VerificationResult`'s completion and `Assurance\Channel`'s reference are each held as
  a `\SensitiveParameterValue` behind an accessor, so no dump shows them.
- `Secrets\SecretResponse::json()` is the one helper that reveals: it replaces every `RevealedSecret` in the data, at
  any depth of nested arrays, by its plaintext, and sends the response with `Cache-Control: no-store` and
  `Pragma: no-cache`. A `RevealedSecret` inside another object is not revealed, so encoding it throws.
- `SecretResponse::withoutStoring()` sets `Cache-Control: no-store` and `Pragma: no-cache` on any Symfony response,
  replacing every caching directive it had (`public`, `max-age` and the rest), and returns the same response. The
  `mfa.no-store` middleware, `Secrets\NoStore`, applies it to every response of the routes it is placed on.
- While `mfa.secrets.redact` is on, every channel in `logging.channels` lists `Secrets\RedactSecretsInLogs` in its
  `tap`, added once, after the channel's own taps, when the package boots, and every channel the log manager resolved
  before then is given the tap at once, since the manager keeps a resolved channel and never taps it again.
- The tap leaves a Monolog logger with exactly one `Secrets\RedactSecrets` processor, the last it runs: Monolog runs
  the processor pushed last first, so the tap takes every processor off, pushes one `RedactSecrets`, and pushes the
  others back in their order. The processors listed in a channel's `processors`, and Laravel's shared context
  processor, pushed after the tap, all run before it, so it sees everything they add. A stack built from tapped
  channels holds one. Processors of a handler run after it.
- `RedactSecrets` redacts the message, the context and the extra data of a record through `Secrets\Redactor`: a
  `RevealedSecret`, `\SensitiveParameterValue` or code message (`Codes\MfaCodeMessage`, or a `SendQueuedMailable`
  sending one) anywhere; the whole value of a string key that names a secret, a code or a destination (`secret`,
  `totp_secret`, `code`, `codes`, `otp`, `one_time_code`, `recovery_code`, `recovery_codes`, `destination`, `address`,
  `email`, `phone`, `phone_number`, `to`, `recipient`, `provisioning_uri`, `otpauth_uri`, `grant`, `enrollment_grant`,
  compared without case, underscores, hyphens or spaces); every `otpauth://` or `otpauth-migration://` URI in a string.
  Integer keys are never read as names. Everything else is kept, masked destinations included.
- `RedactSecrets` first normalises the context and the extra data once (`Redactor::normalise()`): every object other
  than a secret value, a code message, an exception, a date or an enum becomes its logged form keyed by its class,
  within the same bounds as the redaction. A value under a key above is left as it is, with no method of an object in
  it called, since the redaction replaces it whole; only the strings it already holds are collected. From that form,
  before redacting anything, it collects the sensitive values through `Secrets\SensitiveValues`: those marked as
  sensitive, those under a key above (in an object's form too), a code message's code and recipients' addresses, and
  what a logged exception's chain recorded in its traces. It then redacts that same form, so whatever the redaction
  reaches in an object was collected.
- The collected values leave the record's message, so a message copied from an exception before it was scrubbed is
  covered, and every logged exception's chain is scrubbed with them, each kept to its kind (known or collected), so a
  code logged beside an exception leaves the exception's and its previous ones' messages even when PHP recorded no
  arguments.
- An object in a record is turned into what Monolog would log for it, keyed by its class, and that is redacted: an
  `Arrayable`'s array form (so a collection holding a `RevealedSecret` is redacted rather than refusing to encode),
  a `JsonSerializable`'s JSON form, a `Stringable`'s string form, or any other object's public properties. An
  exception is scrubbed in place and kept; a date or an enum is kept.
- The walk is bounded: an array or object deeper than ten levels becomes `[truncated]`, and an array keeps its first
  thousand entries, the rest replaced by one `...` entry of `[truncated]`, so a recursive or very large context ends.
- `Secrets\ExceptionScrubber::scrub()` rewrites the recorded trace and the message of an exception and of every
  previous one in place. Every argument of a frame that touches the package (its `class` in the package's namespace,
  or its `file` under the package's source directory) becomes `[redacted]`.
- Every value is collected from the whole chain before anything is scrubbed, in two kinds (`SensitiveValues`).
  Collected: every string among the arguments of a frame that touches the package, every value any frame marks as
  sensitive (the value of a `\SensitiveParameterValue`, the plaintext of a `RevealedSecret`), and every value under a
  key above, at any depth up to ten levels. Known: a code message's code and its recipients' (`to`, `cc`, `bcc`)
  addresses, and the values the caller gives `scrub()`. Empty strings, `null` and `[redacted]` are never values.
- In another frame, at any depth, a string becomes `[redacted]` when it contains a known value, whatever its length, or
  is a collected value, or contains one of six characters or more. This covers the facade's own frame, which PHP
  records as `Facade::__callStatic('verify', [..., $code])`, every frame below the package, such as a hasher's or an
  encrypter's, and a rendered mail or SMS body below a sender.
- A code message, or a queued job sending one, becomes `[redacted]` in every frame, nested in an array too.
- The message of every exception in the chain loses each occurrence of a known value, and of a collected value of six
  characters or more, replaced by `[redacted]` (longest first, with no marker searched again); a message that is a
  shorter collected value becomes `[redacted]`; every `otpauth://` URI becomes `[redacted]`. The rest of the message
  is kept.
- Other arguments of other frames are kept, redacted as `Redactor` redacts a context but with other objects kept as
  they are. Frames without arguments are kept as they are. Scrubbing is idempotent.
- `Codes\CodeService` wraps the driver's `deliver()` call alone in a catch: a throwable is scrubbed with the code and
  the factor's destination given as known values, so they leave every message and frame of its chain whether or not
  PHP recorded arguments, and `Exceptions\CodeDeliveryFailedException` is thrown, naming the factor's type and masked
  destination, carrying its `FactorSummary`, with the scrubbed throwable as its previous one. Rethrowing inside the
  factor state transaction still rolls it back, so the code is not kept.
- `MfaCodeMessage::send()` catches a throwable from Laravel's `Mailable::send()`, scrubs it with its own code and
  recipients' addresses as known values, and rethrows it. A queue worker runs that method for a queued message, so
  the failure is scrubbed before the worker dispatches `JobExceptionOccurred` or reports it. The values are read from
  the message for that call only: nothing is static, so nothing collected for one job or one delivery reaches another.
- Both delivery scrubs run whatever `mfa.secrets.redact` says.
- The sender contracts, every shipped sender (`MailEmailSender`, the null and fake senders) and the code drivers'
  `send()` and `deliver()` mark each parameter carrying a code, a message holding one or a destination
  `#[\SensitiveParameter]`, and so does `CodeService`'s delivery helper for the issued code.
- While `mfa.secrets.redact` is on, Laravel's exception handler scrubs every exception it reports through a `report`
  callback the package registers on it, whether the handler was built before the package booted or is built after; an
  exception in a log record's context is scrubbed by the processor as well.
- `mfa.secrets.redact` fails safe: only a value `FILTER_VALIDATE_BOOL` reads as false (`false`, `0`, `off`, `no`)
  turns redaction off; `null`, an empty string and anything malformed leave it on. The middleware alias is registered
  either way.
- TOTP secrets are encrypted with the application's encrypter through the factor model's `encrypted` cast, so a secret
  encrypted under a key listed in `app.previous_keys` (`APP_PREVIOUS_KEYS`) decrypts and verifies after the key is
  rotated. Nothing re-encrypts it under the new key.

## Success Path

- The enrolment flow returns the TOTP secret and provisioning URI as `RevealedSecret` values; the application's
  controller returns `SecretResponse::json([...])`; the body carries the plaintext, the response carries `no-store`,
  and the route's `mfa.no-store` middleware sets the same headers again on the way out.
- A log call anywhere in the application writes `['code' => $code]`, or Laravel's shared context holds a code, or a
  channel's own processor adds one; the channel's `RedactSecrets` processor runs after every other processor of the
  logger and before any handler, and the record written holds `[redacted]`.
- An exception thrown below a call such as `Mfa::verify(Submission::factor($id, $code))` is reported. The package's
  `report` callback scrubs it before the handler logs it: the frames inside the package lose every argument, and the
  facade's frame and every frame below the package lose the code, so the trace's string form shows `'[redacted]'` where
  it would show the start of the code. The context the exception's `context()` gives is redacted by the processor.
- A bound SMS sender throws, quoting the phone number and the message. `CodeService` scrubs the code and the number
  from the sender's exception and every previous one, and throws `CodeDeliveryFailedException` naming the factor at
  its masked number; the transaction rolls back and no code is kept.
- A queue worker runs a queued `MfaCodeMessage` whose transport throws, quoting the recipient and the rendered body.
  The message's `send()` scrubs the code and the address before rethrowing, so the worker's event listeners and its
  report see neither.

## Failure / Edge Cases

- A `RevealedSecret` placed in a `response()->json()` body, a session, a cache, a queued job or a log line built by
  concatenation throws `SecretNotRevealedException` instead of sending or keeping the secret. A `RevealedSecret`
  placed in a log context without the processor (redaction off, or a channel added after boot) also throws when
  Monolog normalises it, since it refuses JSON encoding.
- A channel configured after the package boots, and the emergency logger Laravel builds when a channel fails, are not
  tapped. A processor pushed onto a channel's logger after the tap runs before it, so is covered too. A channel whose
  `tap` is not a list, and a channel that is not an array, are left as they are. Laravel fires `MessageLogged` with
  the context it was given before Monolog runs any processor, so its listeners see the context unredacted.
- A reporter registered on the exception handler before the package's callback, typically from `bootstrap/app.php`,
  sees the exception before it is scrubbed; the guide shows calling `ExceptionScrubber::scrub()` first there. An
  exception handler other than Laravel's is left as it is.
- A key whose name merely contains a sensitive word (`status_code`, `masked_destination`) is kept, and a secret placed
  under an ordinary key as a plain string is kept unless it is a provisioning URI: the redaction is by type, by key and
  by URI shape, not by guessing which strings are secret. Traces are the exception: there, what the package passed
  on is known, so it is redacted wherever it reappears.
- Propagation over-redacts rather than under-redacts: a string the package passed on that is not secret, such as a
  factor type, is redacted from the other frames too, and every string containing one of six characters or more. An
  argument an exception was thrown with before it reached the package, such as a code passed to a facade whose root
  failed to resolve, is not known to be the package's and is kept.
- An object in a trace's arguments, a code message aside, is kept as it is: its string form is its class name, and
  turning it into its array form while an exception is handled could run code with side effects. An error tracker
  that reads an object's properties from a trace should run with `zend.exception_ignore_args` on.
- With `zend.exception_ignore_args` on, nothing can be collected from a trace; only known values, those the delivery
  scrubs give and those a message copied into a log context carries, are redacted from messages.
- A message is redacted of every collected value of six characters or more, so a string a package frame received that
  is not secret, such as a table name, is redacted from a message too. A code message's code is redacted by value only
  as it is: a subclass that renders it reformatted (`482 915`) is not matched.
- A sender's failure, the default senders' `SenderNotConfiguredException` and a driver's
  `MissingDestinationException` included, surfaces as `CodeDeliveryFailedException`, with the original as its
  previous exception.
- A key dropped from both `APP_KEY` and `APP_PREVIOUS_KEYS` leaves the secrets encrypted under it undecryptable:
  reading one throws `DecryptException`, which surfaces as a server error rather than a wrong code.

## Implementation Anchors

- `src/Secrets/RevealedSecret.php`: the value, `reveal()`, and the refusing magic methods.
- `src/Secrets/SecretResponse.php`: `json()`, `withoutStoring()`, and the recursive reveal.
- `src/Secrets/NoStore.php`: the `mfa.no-store` middleware.
- `src/Secrets/Redactor.php`: the redacted keys, the provisioning URI pattern, the bounded walk over values and
  objects, code messages, and the redaction of sensitive values in trace arguments and messages.
- `src/Secrets/SensitiveValues.php`: the two kinds of value, their collection from arguments, log values and code
  messages, and how each matches a string and leaves a message.
- `src/Secrets/ExceptionScrubber.php`: the walk over the exception chain, the package frame test, the values
  collected and given, and the messages.
- `src/Codes/CodeService.php` (`deliver()`), `src/Codes/MfaCodeMessage.php` (`send()`) and
  `src/Exceptions/CodeDeliveryFailedException.php`: the delivery scrubs and the exception that replaces a failure.
- `src/Secrets/RedactSecrets.php` and `src/Secrets/RedactSecretsInLogs.php`: the Monolog processor and the tap.
- `src/Secrets/SecretBindings.php`: the middleware alias, the tap added to every channel and applied to every resolved
  one, and the `report` callback.
- `src/Secrets/SecretSettings.php`: the fail-safe reading of `mfa.secrets.redact`.
- `src/Exceptions/SecretNotRevealedException.php`: the refusal.
- `src/Models/Factor.php`: the `encrypted` cast on `secret`.

## Authoritative Tests

- `tests/Unit/Secrets/RevealedSecretTest.php`
  every refusal, and every dump showing no plaintext
- `tests/Unit/Secrets/SecretResponseTest.php`
  `testJsonRevealsEverySecretInTheBody`, `testWithoutStoringReplacesTheCachingAllowed`
- `tests/Feature/Secrets/NoStoreMiddlewareTest.php`
  the header on every response of a route with the middleware, and none without it
- `tests/Unit/Secrets/RedactorTest.php`
  the redacted keys, the kept keys, values, objects, provisioning URIs, exceptions, the bounds and trace arguments
- `tests/Unit/Secrets/ExceptionScrubberTest.php`
  package frames, propagation to other frames in forged and real traces, messages, values given with and without
  recorded arguments, code messages, the exception chain and idempotence
- `tests/Unit/Secrets/SensitiveValuesTest.php`
  known and collected values, the length threshold, collection from arguments, log values and code messages, bounds
- `tests/Unit/Secrets/RedactSecretsTest.php`
  `testRedactsAMessageCopiedFromAnException`, `testRedactsTheValuesTheRecordHoldsFromItsMessage`,
  `testScrubsALoggedExceptionOfTheValuesTheRecordHolds`, `testRedactsTheValuesAnObjectHoldsFromTheMessage`,
  `testRedactsAnObjectUnderASecretKeyWithoutCallingIt`
- `tests/Unit/Codes/CodeServiceTest.php`
  `testAFailedDeliveryIsScrubbedOfTheCodeAndTheDestination`, with and without recorded arguments
- `tests/Unit/Codes/MfaCodeMessageFailureTest.php`
  a queued message a worker fails to send, a message failing at once, and nothing carried between jobs
- `tests/Unit/Codes/SensitiveDeliveryParametersTest.php`
  every parameter carrying a code, a message or a destination is marked sensitive
- `tests/Unit/Secrets/RedactSecretsInLogsTest.php`
  `testRunsTheProcessorLast`, `testRedactsWhatOtherProcessorsAdd`, `testKeepsOneProcessorRunningLast`
- `tests/Unit/Secrets/SecretBindingsTest.php`
  the taps, the fail-safe switch, and the `report` callback on a handler built before and after boot
- `tests/Integration/Secrets/LogRedactionTest.php`
  a secret in a log's context and its objects, the shared context, a channel's own processors, a channel resolved
  before boot, a reported exception's context and message, and a code passed through the facade in a real trace
- `tests/Integration/Secrets/KeyRotationTest.php`
  `testASecretEncryptedUnderAPreviousKeyVerifies`, `testASecretUnderADroppedKeyDoesNotDecrypt`

## Change Triggers

Update this note when any of the following change:

- how a `RevealedSecret` holds or refuses to give up its plaintext
- the headers `SecretResponse` and `mfa.no-store` set
- the keys, values, objects or string shapes `Redactor` redacts, or its bounds
- which trace frames `ExceptionScrubber` treats as the package's, or which values it carries to other frames and
  messages
- where a delivery failure is caught and scrubbed, or what replaces it
- how the tap and the `report` callback are attached, or what `mfa.secrets.redact` turns off
- the encryption of TOTP secrets, or how a rotated key is honoured
