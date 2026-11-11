<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Translation\MessageSelector;

/**
 * Consumer-facing wording: the current translation, or the shipped English when
 * the fallback chain has nothing usable, since `Translator::get` ends at the
 * key.
 *
 * Resolved per call for Octane. A code line is returned as a template, so the
 * code never reaches the translator or a missing-key handler.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConsumerMessages
{
    /** @var string */
    public const string FURTHER_AUTHENTICATION_REQUIRED = self::NAMESPACE . 'further_authentication_required';

    /** @var string */
    public const string SMS_CODE = self::NAMESPACE . 'sms_code';

    /** @var string */
    public const string EMAIL_SUBJECT = self::NAMESPACE . 'email_subject';

    /** @var string */
    public const string EMAIL_CODE = self::NAMESPACE . 'email_code';

    /** @var string */
    public const string EMAIL_EXPIRY = self::NAMESPACE . 'email_expiry';

    /** @var string */
    public const string EMAIL_IGNORE = self::NAMESPACE . 'email_ignore';

    /** @var string A code line must carry it exactly. */
    public const string CODE_PLACEHOLDER = ':code';

    /** @var string */
    private const string NAMESPACE = 'mfa::messages.';

    /** @var string */
    private const string MINUTES_PLACEHOLDER = ':minutes';

    /** @var string */
    private const string SHIPPED = __DIR__ . '/../../lang/en/messages.php';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  string  $key
     * @return string
     */
    public static function line(string $key): string
    {
        $line = self::translator()?->get($key);

        return self::isUsable($line, $key) ? $line : self::english($key);
    }

    /**
     * Falls back to English when the line lacks the exact placeholder, so a
     * message is never sent without its code.
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
     * Checked before selection, so an array never reaches the selector, and
     * after, as `One minute|` selects nothing for two.
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
     * Read from the file, never an application's override.
     *
     * @param  string  $key
     * @return string
     */
    public static function english(string $key): string
    {
        // Not require_once, which returns true on later reads
        /** @var array<string, string> $lines */
        $lines = require self::SHIPPED; // NOSONAR

        return $lines[substr($key, strlen(self::NAMESPACE))];
    }

    /**
     * @return ?string
     */
    public static function locale(): ?string
    {
        return self::translator()?->getLocale();
    }

    /**
     * Null before boot, so raising a refusal never raises something else.
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
