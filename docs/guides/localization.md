# Localisation

Every message the package can put in front of a consumer goes through Laravel's translator. Every other answer is a
machine-readable code your application words. Every class name below is relative to `SineMacula\Laravel\Mfa`.

## The messages

The package ships English in `lang/en/messages.php`, under the `mfa` namespace. The keys and their placeholders are
stable names.

| Key                                             | Where it appears          | Placeholders | English                                                                         |
|-------------------------------------------------|---------------------------|--------------|---------------------------------------------------------------------------------|
| `mfa::messages.further_authentication_required` | The route gate's refusal  |              | `Further authentication is required.`                                           |
| `mfa::messages.sms_code`                        | The SMS a code is sent in | `:code`      | `Your verification code is: :code`                                              |
| `mfa::messages.email_subject`                   | The email's subject       |              | `Your verification code`                                                        |
| `mfa::messages.email_code`                      | The email's code line     | `:code`      | `Your verification code is: :code`                                              |
| `mfa::messages.email_expiry`                    | The email's expiry line   | `:minutes`   | `This code expires in :minutes minute.\|This code expires in :minutes minutes.` |
| `mfa::messages.email_ignore`                    | The email's closing line  |              | `If you did not request this code, you can safely ignore this message.`         |

`mfa::messages.email_expiry` is a plural line, chosen by the locale's own rules.

The SMS and email lines are the package's own wording of a code, used where your sender keeps it: the email lines by
`Codes\MfaCodeMessage`, which `Codes\MailEmailSender` sends, and the SMS line by `Codes\SmsCodeText::of()`. A sender
is given the code's neutral details (see [Factor drivers](extending.md#factor-drivers)), so one that writes its own
wording uses none of them.

## Translating them

Write a file per locale at `lang/vendor/mfa/{locale}/messages.php` in your application. It only needs the keys you want
to change, because Laravel overlays it on what the package ships:

```php
// lang/vendor/mfa/fr/messages.php

return [
    'further_authentication_required' => 'Une authentification supplémentaire est requise.',
    'sms_code'                        => 'Votre code de vérification est : :code',
    'email_subject'                   => 'Votre code de vérification',
    'email_code'                      => 'Votre code de vérification est : :code',
    'email_expiry'                    => 'Ce code expire dans :minutes minute.|Ce code expire dans :minutes minutes.',
    'email_ignore'                    => 'Si vous n\'avez pas demandé ce code, vous pouvez ignorer ce message.',
];
```

To start from the English, publish it:

```bash
php artisan vendor:publish --tag=mfa-lang
```

## When a translation cannot be used

Laravel's own fallback chain runs first, so a valid translation in your `app.fallback_locale` is honoured even when it
is not English. When that chain ends with nothing, the shipped English is used, whatever the fallback locale is:

- A missing line, an empty or whitespace-only line, or one that is not a string is replaced by the English.
- A plural line that selects an empty branch, such as `One minute|` for five minutes, is replaced by the English, with
  English plural rules.
- A code line must carry the exact `:code`, not `:Code` or `:CODE`. A line without it is replaced by the English, so a
  usable message goes out rather than one with no code in it.

The promise covers a missing or unusable result only. A `handleMissingKeysUsing()` callback can return any non-empty
string, which cannot be told from a translation, and a translator that throws is left to propagate.

## Lines are plain text

The email escapes each translated line as a whole, then puts the code in, escaped, in place of `:code`. A translation
cannot add markup: `<b>` shows as written. A subclass of `Codes\MfaCodeMessage` overriding `renderHtml()` or `content()`
writes its own markup, and is responsible for escaping it.

The code is never passed to the translator. It stays out of its arguments, its replacements and any missing-key
callback, so a translation layer that logs what it is asked does not see one.

## Which locale

| Message     | Its locale                                                                             |
|-------------|----------------------------------------------------------------------------------------|
| The refusal | The current locale when the exception is raised                                        |
| The SMS     | The current locale when `SmsCodeText::of()` words it                                   |
| The email   | The message's own locale if it chose one, otherwise the current locale when it is sent |

A locale middleware must run before `mfa`, or the refusal is raised in the default locale. Place it ahead of `mfa` in
the route's middleware, and in the priority list too if you have one (see
[Route middleware](middleware.md#the-refusals-wording)).

The email keeps the locale it was sent in, so a queued one renders in that locale on a worker, whose own locale is put
back afterwards. A `Codes\MfaCodeMessage` subclass that sets a locale in its constructor keeps it.

The package does not read `HasLocalePreference`: it words a message in the current locale, so which locale to use is
your application's to set before the call, or your sender's to choose from the message's `recipient()`. A custom
`Contracts\EmailSender` calling `Mail::to($user)` still gets Laravel's preference for that user.

## What is not translated

- The challenge header. `InsufficientAuthenticationException::wwwAuthenticate()` always uses the shipped English,
  ignoring any override of `en`: RFC 6750 makes `error_description` a diagnostic for a developer and restricts it to a
  subset of ASCII that excludes `"` and `\`.
- Laravel's stock HTML `401` page, which shows its own `__('Unauthorized')` and not the exception's message. The
  translated refusal is on the JSON answer, or on whatever your own rendering sends.
- Internal or operator text: `OperationRefusedException` detail, `VerificationResult::$detail`, `mfa:check` and
  configuration exceptions. These can appear in a debug response; the promise is for production.
- Codes your application words: `Enums\FailureReason`, `Enums\RequirementPart` and `insufficient_user_authentication`.
- Supplied data, such as a factor's label, and the words a custom mailable or sender adds.
