# Consumer Messages

## Purpose

This note records which of the package's words can reach a consumer, how each is translated, what happens when a
translation cannot be used, and what is deliberately left out.

## Invariants

- What can reach a consumer in words is the `401` of the route gate, the email's subject and three body lines, and the
  SMS text. Each goes through `Support\ConsumerMessages`, under a key in `lang/en/messages.php`. That file is the one
  source of the English; no constant repeats it.
- The keys are American identifiers and stable names; the wording is British. `ConsumerMessages` has one constant per
  shipped key, and a test holds the two lists equal.
- The translator is resolved through `Container::getInstance()` on every call, so under Octane it is the sandbox's.
  Nothing kept holds a translator, a locale or a template: the driver holds no SMS wording, as the words belong to the
  locale the message is sent in.
- There is no configured SMS wording. A config string silently defeats every locale, so the only way to change the text
  is a translation.
- A code stays out of the translator's arguments, replacement arrays and missing-key callbacks: `codeLine()` returns a
  template, and the caller substitutes with `str_replace`. This is a claim about the translator and not about every
  backtrace, so the `#[\SensitiveParameter]` marks and `Secrets\ExceptionScrubber` stay.
- A code line needs the exact literal `:code`. A line lacking it is replaced by the English: a usable message rather
  than none, or one with no code.
- Every line is plain text. `renderHtml()` escapes the whole translated line, then replaces `:code` with `<strong>`, the
  escaped code and `</strong>`, so a translation cannot inject markup; a subclass overriding `renderHtml()` still can.
- `wwwAuthenticate()` uses `ConsumerMessages::english()`, read from the shipped file by `require`, never the translator.
  RFC 6750 makes `error_description` a developer's diagnostic in a subset of ASCII excluding `"` and `\`, so neither a
  translation nor an application's override of `en` may reach it.

## Success Path

- `ConsumerMessages::line()` asks the translator with no replacements. Laravel's fallback chain runs first, so a valid
  translation in a non-English fallback locale is honoured before the shipped English.
- The refusal is translated in `InsufficientAuthenticationException`'s constructor, so every raiser gets it, in the
  locale when it is raised. Neither the middleware passing a message in nor a render callback is needed.
- The SMS renders when it is sent, in the current locale.
- `EmailDriver::send()` builds the message, then captures the current locale on one that chose none. `Mailable::send()`
  and `render()` enter that locale before building the envelope and the content, and `SerializesModels` carries it
  through the queue, encryption included, so a queued subclass renders in the person's locale on the worker, and the
  worker's is put back.
- `minutesLine()` looks at the line first, since an array would otherwise reach the selector; calls `choice()`; then
  looks at the selected answer, since `One minute|` passes the first look and selects nothing for two. On any unusable
  answer it runs `MessageSelector::choose()` over the shipped line with English plural rules, whatever the locale.

## Failure / Edge Cases

- `Translator::get` ends at the key, and shipping `en` does not append English to every fallback chain, which is why an
  answer equal to the key, an empty or whitespace-only string, or anything that is not a string falls back.
- With no translator bound, as when `Container::getInstance()` has none, the line is the English and the locale `null`:
  raising a refusal must never raise something else.
- A missing-key handler can return any non-empty string, which cannot be told from a translation. A translator that
  throws is left to propagate, with no blanket catch. Both limit the promise, which is English for a missing or unusable
  result.
- Laravel's stock HTML `401` page shows its own `__('Unauthorized')` and not the exception's message. Only the JSON
  answer carries the translated refusal.
- A locale middleware must run before `mfa`, or the refusal is raised in the default locale.
- `HasLocalePreference` is not read, because the driver is given a factor and the sender an address. A custom
  `EmailSender` using `Mail::to($user)` still gets Laravel's preference, which `PendingMail` applies over the captured
  locale.
- Internal or operator text is out of scope: `OperationRefusedException` detail, `VerificationResult::$detail`,
  `mfa:check` and configuration exceptions. These can appear in a debug response; the promise is for production. So are
  codes the application words (`FailureReason`, `RequirementPart`, `insufficient_user_authentication`), supplied data
  such as factor labels, and the words a custom mailable or sender adds.

## Implementation Anchors

- `lang/en/messages.php`; `src/Support/ConsumerMessages.php`.
- `src/MfaServiceProvider.php`: `boot()`, `offerPublishing()`, tag `mfa-lang`.
- `src/Exceptions/InsufficientAuthenticationException.php`: the constructor and `wwwAuthenticate()`.
- `src/Codes/MfaCodeMessage.php`: `envelope()`, `renderHtml()`.
- `src/Drivers/SmsDriver.php`, `src/Drivers/EmailDriver.php`: `send()`.

## Authoritative Tests

- `tests/Unit/Support/ConsumerMessagesTest.php`: keys and constants, unusable answers on each path, fallback chains, no
  translator, the placeholder, plural rules.
- `tests/Feature/Localization/RefusalWordingTest.php`: JSON through the kernel, the stock HTML page, the character set
  of the challenge header against a translation and an override.
- `tests/Feature/Localization/CodeMessageWordingTest.php`: mail and SMS through the kernel, a line losing its code, a
  recording translator, escaping, the captured and an explicit locale, the encrypted queue round trip.
- `tests/Unit/MfaServiceProviderTest.php`: the publish tag and the absent configuration key.

## Change Triggers

Revisit this note when the package gains a message a consumer can see, when a line takes a new placeholder, when the
code needs to reach a translated line by any other path, or when Laravel's `Translator` changes how it answers a missing
key.
