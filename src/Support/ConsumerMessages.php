<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Translation\MessageSelector;

/**
 * The wording of everything the package can put in front of a consumer: the
 * translation for the current locale, or the English the package ships when the
 * translator has nothing usable.
 *
 * Laravel's fallback chain runs first, so a valid translation in a non-English
 * fallback locale is honoured. The English is needed because `Translator::get`
 * ends at the key, and shipping `en` does not add English to every chain.
 *
 * The translator is resolved on every call, so under Octane it is the sandbox's
 * and neither it nor its locale is kept. No code ever reaches it: a code line
 * is returned as a template for the caller to fill, keeping the code out of the
 * translator's arguments, its replacements and any missing-key handler.
 *
 * The promise is limited to a missing or unusable result. A missing-key handler
 * may return any non-empty string, which cannot be told from a translation, and
 * a translator that throws is left to propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConsumerMessages
{
    /** @var string The route gate's refusal. */
    public const string FURTHER_AUTHENTICATION_REQUIRED = self::NAMESPACE . 'further_authentication_required';

    /** @var string The SMS a code is sent in. */
    public const string SMS_CODE = self::NAMESPACE . 'sms_code';

    /** @var string The subject of the email a code is sent in. */
    public const string EMAIL_SUBJECT = self::NAMESPACE . 'email_subject';

    /** @var string The email's line carrying the code. */
    public const string EMAIL_CODE = self::NAMESPACE . 'email_code';

    /** @var string The email's line saying when the code expires, by the minutes left. */
    public const string EMAIL_EXPIRY = self::NAMESPACE . 'email_expiry';

    /** @var string The email's line for someone who did not ask for a code. */
    public const string EMAIL_IGNORE = self::NAMESPACE . 'email_ignore';

    /** @var string The placeholder a code line must carry, exactly; the code replaces it. */
    public const string CODE_PLACEHOLDER = ':code';

    /** @var string What every key starts with: the package's namespace and its file. */
    private const string NAMESPACE = 'mfa::messages.';

    /** @var string The placeholder of a line that says how many minutes. */
    private const string MINUTES_PLACEHOLDER = ':minutes';

    /** @var string The file holding the English the package ships. */
    private const string SHIPPED = __DIR__ . '/../../lang/en/messages.php';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The line in the current locale with no replacements, or the shipped
     * English when there is no usable translation.
     *
     * @param  string  $key
     * @return string
     */
    public static function line(string $key): string
    {
        $line = self::translator()?->get($key);

        return self::isUsable($line, $key) ? $line : self::english($key);
    }

    /**
     * The line as a template for the caller to put the code in, or the shipped
     * English when the line lacks the exact placeholder, so a message is never
     * sent without its code.
     *
     * @param  string  $key
     * @return string
     */
    public static function codeLine(string $key): string
    {
        $line = self::line($key);

        return str_contains($line, self::CODE_PLACEHOLDER) ? $line : self::english($key);
    }

    /**
     * The plural line for the minutes, or the shipped English, by English
     * plural rules whatever the locale, when there is no usable translation.
     *
     * The line is looked at before it is selected from, because an array would
     * otherwise reach the selector, and after, because `One minute|` passes the
     * first look and selects nothing for two.
     *
     * @param  string  $key
     * @param  int  $minutes
     * @return string
     */
    public static function minutesLine(string $key, int $minutes): string
    {
        $translator = self::translator();

        if ($translator !== null && self::isUsable($translator->get($key), $key)) {
            $line = $translator->choice($key, $minutes, ['minutes' => $minutes]);

            if (self::isUsable($line, $key)) {
                return $line;
            }
        }

        $english = (new MessageSelector)->choose(self::english($key), $minutes, 'en');

        return is_string($english) ? str_replace(self::MINUTES_PLACEHOLDER, (string) $minutes, $english) : self::english($key);
    }

    /**
     * The line the package ships, read from its file, never an application's
     * override.
     *
     * @param  string  $key
     * @return string
     */
    public static function english(string $key): string
    {
        // Not require_once: it answers true from the second read on
        /** @var array<string, string> $lines */
        $lines = require self::SHIPPED; // NOSONAR

        return $lines[substr($key, strlen(self::NAMESPACE))];
    }

    /**
     * The translator's current locale, or `null` when none is bound.
     *
     * @return ?string
     */
    public static function locale(): ?string
    {
        return self::translator()?->getLocale();
    }

    /**
     * The translator bound now, if there is one: raising a refusal must never
     * raise something else because the application is not fully booted.
     *
     * @return ?\Illuminate\Contracts\Translation\Translator
     */
    private static function translator(): ?Translator
    {
        $container = Container::getInstance();

        if (!$container->bound('translator')) {
            return null;
        }

        return $container->make('translator');
    }

    /**
     * Whether the translator's answer can be said: a string, not the key it
     * ends at when it has nothing, and not empty or only whitespace.
     *
     * @param  mixed  $line
     * @param  string  $key
     * @return bool
     *
     * @phpstan-assert-if-true string $line
     */
    private static function isUsable(mixed $line, string $key): bool
    {
        return is_string($line) && $line !== $key && trim($line) !== '';
    }
}
