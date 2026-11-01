# Secrets in Responses and Logs

## Purpose

This note records how the secrets the package returns once (TOTP secrets, provisioning URIs and recovery codes) reach
the person and nothing else: the value they are returned in, the response that sends them without a cache keeping it,
the redaction that keeps them, codes and full destinations out of logs and exception traces, and the key rotation TOTP
secrets survive. It follows the rule `sinemacula/laravel-authentication` follows for secrets in responses, so a
middleware placed on a route covers any secret the route sends, whichever package returned it.

## Invariants

- A secret is returned as a `Secrets\RevealedSecret`, which holds its plaintext as a `\SensitiveParameterValue`. The
  plaintext leaves it only through `reveal()`. `__toString()`, `jsonSerialize()`, `__serialize()` and
  `__unserialize()` throw `Exceptions\SecretNotRevealedException`, a `LogicException`; `__debugInfo()` gives a
  `[redacted]` marker, and the `\SensitiveParameterValue` gives `print_r`, `var_dump`, `var_export`, array casts and
  Symfony's VarDumper nothing. The class is final and readonly.
- `Secrets\SecretResponse::json()` is the one helper that reveals: it replaces every `RevealedSecret` in the data, at
  any depth of nested arrays, by its plaintext, and sends the response with `Cache-Control: no-store` and
  `Pragma: no-cache`. A `RevealedSecret` inside another object is not revealed, so encoding it throws.
- `SecretResponse::withoutStoring()` sets `Cache-Control: no-store` and `Pragma: no-cache` on any Symfony response,
  replacing every caching directive it had (`public`, `max-age` and the rest), and returns the same response. The
  `mfa.no-store` middleware, `Secrets\NoStore`, applies it to every response of the routes it is placed on.
- While `mfa.secrets.redact` is on, every channel in `logging.channels` lists `Secrets\RedactSecretsInLogs` in its
  `tap`, added once, after the channel's own taps, when the package boots. The tap pushes one `Secrets\RedactSecrets`
  processor onto a Monolog logger that has none, so a stack built from tapped channels holds one.
- `RedactSecrets` redacts the message, the context and the extra data of a record through `Secrets\Redactor`: a
  `RevealedSecret` or `\SensitiveParameterValue` anywhere; the whole value of a string key that names a secret, a code
  or a destination (compared without case, underscores, hyphens or spaces); every `otpauth://` or
  `otpauth-migration://` URI in a string. Integer keys are never read as names. Arrays are walked at any depth.
  Everything else is kept, masked destinations included.
- `Secrets\TraceScrubber::scrub()` rewrites the recorded trace of an exception and of every previous one in place.
  Every argument of a frame that touches the package (its `class` in the package's namespace, or its `file` under the
  package's source directory) becomes `[redacted]`; other frames keep their arguments, redacted as `Redactor` redacts
  a context. Frames without arguments are kept as they are. Scrubbing is idempotent.
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

- An enrolment starts and returns the TOTP secret and provisioning URI as `RevealedSecret` values. The application's
  controller returns `SecretResponse::json([...])`; the body carries the plaintext, the response carries `no-store`,
  and the route's `mfa.no-store` middleware sets the same headers again on the way out.
- A log call anywhere in the application writes `['code' => $code]`, or Laravel's shared context holds a code; the
  channel's `RedactSecrets` processor runs after Laravel's context processor and before any handler, and the record
  written holds `[redacted]`.
- An exception thrown below a call such as `Mfa::verify($driver, $factor, $code)` is reported. The package's `report`
  callback scrubs its trace before the handler logs it, so the trace's string form shows `'[redacted]'` where it would
  show the start of the code, and the context the exception's `context()` gives is redacted by the processor.

## Failure / Edge Cases

- A `RevealedSecret` placed in a `response()->json()` body, a session, a cache, a queued job or a log line built by
  concatenation throws `SecretNotRevealedException` instead of sending or keeping the secret. A `RevealedSecret`
  placed in a log context without the processor (redaction off, or a channel added after boot) also throws when
  Monolog normalises it, since it refuses JSON encoding.
- A channel configured after the package boots, and the emergency logger Laravel builds when a channel fails, are not
  tapped. A channel whose `tap` is not a list, and a channel that is not an array, are left as they are. Laravel fires
  `MessageLogged` with the context it was given before Monolog runs any processor, so its listeners see the context
  unredacted.
- A reporter registered on the exception handler before the package's callback, typically from `bootstrap/app.php`,
  sees the exception before it is scrubbed; the guide shows calling `TraceScrubber::scrub()` first there. An exception
  handler other than Laravel's is left as it is.
- A key whose name merely contains a sensitive word (`status_code`, `masked_destination`) is kept, and a secret placed
  under an ordinary key as a plain string is kept unless it is a provisioning URI: the redaction is by type, by key and
  by URI shape, not by guessing which strings are secret.
- A key dropped from both `APP_KEY` and `APP_PREVIOUS_KEYS` leaves the secrets encrypted under it undecryptable:
  reading one throws `DecryptException`, which surfaces as a server error rather than a wrong code.

## Implementation Anchors

- `src/Secrets/RevealedSecret.php`: the value, `reveal()`, and the refusing magic methods.
- `src/Secrets/SecretResponse.php`: `json()`, `withoutStoring()`, and the recursive reveal.
- `src/Secrets/NoStore.php`: the `mfa.no-store` middleware.
- `src/Secrets/Redactor.php`: the redacted keys, the provisioning URI pattern, and the walk over values.
- `src/Secrets/TraceScrubber.php`: the walk over the exception chain and the package frame test.
- `src/Secrets/RedactSecrets.php` and `src/Secrets/RedactSecretsInLogs.php`: the Monolog processor and the tap.
- `src/Secrets/SecretBindings.php`: the middleware alias, the tap added to every channel, and the `report` callback.
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
  the redacted keys, the kept keys, values, provisioning URIs and exceptions
- `tests/Unit/Secrets/TraceScrubberTest.php`
  package frames, other frames, the exception chain and idempotence
- `tests/Unit/Secrets/SecretBindingsTest.php`
  the taps, the fail-safe switch, and the `report` callback on a handler built before and after boot
- `tests/Integration/Secrets/LogRedactionTest.php`
  a secret in a log's context, the shared context, a reported exception's context and a trace argument
- `tests/Integration/Secrets/KeyRotationTest.php`
  `testASecretEncryptedUnderAPreviousKeyVerifies`, `testASecretUnderADroppedKeyDoesNotDecrypt`

## Change Triggers

Update this note when any of the following change:

- how a `RevealedSecret` holds or refuses to give up its plaintext
- the headers `SecretResponse` and `mfa.no-store` set
- the keys, values or string shapes `Redactor` redacts
- which trace frames `TraceScrubber` treats as the package's
- how the tap and the `report` callback are attached, or what `mfa.secrets.redact` turns off
- the encryption of TOTP secrets, or how a rotated key is honoured
