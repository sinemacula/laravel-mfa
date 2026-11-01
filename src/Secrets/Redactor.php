<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Contracts\Support\Arrayable;

/**
 * Replaces the secrets, codes and full destinations in a set of values, such as
 * a log record's context or a trace frame's arguments, with `[redacted]`.
 *
 * A value is redacted when it is a `RevealedSecret`, a
 * `\SensitiveParameterValue` or a code message (an `MfaCodeMessage`, or a
 * queued job sending one), or when its key names a secret, a code or a
 * destination (`secret`, `totp_secret`, `code`, `codes`, `otp`,
 * `one_time_code`, `recovery_code`, `recovery_codes`, `destination`, `address`,
 * `email`, `phone`, `phone_number`, `to`, `recipient`, `provisioning_uri`,
 * `otpauth_uri`, compared without case, underscores, hyphens or spaces, so
 * `recoveryCodes` and `phoneNumber` count). An `otpauth://` provisioning URI is
 * redacted wherever it appears in a string.
 *
 * In a log's values, an exception is scrubbed in place by `ExceptionScrubber`,
 * of the sensitive values the record holds too, a date or an enum is kept, and
 * any other object is first turned into what Monolog would log for it, keyed by
 * its class (see `normalise()`), so a secret held in an object cannot slip
 * past. In a trace's arguments, other objects are kept as they are, and a
 * string that is, or contains, a sensitive value collected for the scrub is
 * redacted too (see `SensitiveValues`).
 *
 * The walk is bounded: an array or object deeper than ten levels is replaced
 * with `[truncated]`, as is everything after an array's first thousand entries,
 * so a recursive or very large value cannot exhaust memory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Redactor
{
    /** @var string The marker that replaces what the walk does not reach. */
    public const string TRUNCATED = '[truncated]';

    /** @var int The deepest level the walk reaches; deeper arrays and objects are truncated. */
    public const int MAX_DEPTH = 10;

    /** @var int The most entries of one array the walk keeps. */
    private const int MAX_ITEMS = 1000;

    /** @var list<string> The keys whose values are redacted, without case, underscores, hyphens or spaces. */
    private const array KEYS = [
        'address',
        'code',
        'codes',
        'destination',
        'email',
        'onetimecode',
        'otp',
        'otpauthuri',
        'phone',
        'phonenumber',
        'provisioninguri',
        'recipient',
        'recoverycode',
        'recoverycodes',
        'secret',
        'to',
        'totpsecret',
    ];

    /** @var string An `otpauth://` provisioning URI, which carries the TOTP secret. */
    private const string PROVISIONING_URI = '~otpauth(?:-migration)?://\S*~i';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A log's values with every secret, code and full destination in them
     * redacted, each exception in them scrubbed of the sensitive values given
     * too.
     *
     * @param  array<array-key, mixed>  $values
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return array<array-key, mixed>
     */
    public static function redact(array $values, ?SensitiveValues $sensitive = null): array
    {
        return self::redactNormalised(self::normalise($values), $sensitive ?? SensitiveValues::none());
    }

    /**
     * A log's values already normalised (see `normalise()`), with every secret,
     * code and full destination in them redacted, each exception in them
     * scrubbed of the sensitive values given too.
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return array<array-key, mixed>
     */
    public static function redactNormalised(array $values, SensitiveValues $sensitive): array
    {
        return self::redactArray($values, 0, false, $sensitive);
    }

    /**
     * A log's value with every secret in it redacted: a secret value itself,
     * provisioning URIs in a string, the secrets of an array or an object; an
     * exception is scrubbed in place.
     *
     * @param  mixed  $value
     * @return mixed
     */
    public static function value(mixed $value): mixed
    {
        return self::redactValue(self::normaliseValue($value, 0), 0, false, SensitiveValues::none());
    }

    /**
     * A log's values with every object in them turned into what Monolog would
     * log for it, keyed by its class: an `Arrayable`'s array form, a
     * `JsonSerializable`'s JSON form, a `Stringable`'s string form or any other
     * object's public properties, themselves normalised. Secret values, code
     * messages, exceptions, dates and enums, and every value under a key naming
     * a secret, a code or a destination, are kept as they are. The walk is
     * bounded as the redaction is, so the values collected from the result (see
     * `SensitiveValues`) are those the redaction then reaches.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    public static function normalise(array $values): array
    {
        return self::normaliseArray($values, 0);
    }

    /**
     * A trace frame's arguments with every secret in them redacted, and every
     * string the sensitive values collected for the scrub match. Objects other
     * than code messages are kept as they are.
     *
     * @param  array<array-key, mixed>  $arguments
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return array<array-key, mixed>
     */
    public static function arguments(array $arguments, ?SensitiveValues $values = null): array
    {
        return self::redactArray($arguments, 0, true, $values ?? SensitiveValues::none());
    }

    /**
     * A message, an exception's or a log record's, with every occurrence of the
     * sensitive values in it redacted, and every provisioning URI.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return string
     */
    public static function redactMessage(string $message, SensitiveValues $values): string
    {
        return self::redactString($values->redactIn($message));
    }

    /**
     * The string with every provisioning URI in it redacted.
     *
     * @param  string  $value
     * @return string
     */
    public static function redactString(string $value): string
    {
        return preg_replace(self::PROVISIONING_URI, RevealedSecret::REDACTED, $value) ?? RevealedSecret::REDACTED;
    }

    /**
     * Whether the key names a secret, a code or a destination.
     *
     * @param  string  $key
     * @return bool
     */
    public static function namesASecret(string $key): bool
    {
        return in_array(strtolower(str_replace(['_', '-', ' '], '', $key)), self::KEYS, true);
    }

    /**
     * The array with every secret in it redacted, keeping its first thousand
     * entries.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $depth
     * @param  bool  $trace
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return array<array-key, mixed>
     */
    private static function redactArray(array $values, int $depth, bool $trace, SensitiveValues $sensitive): array
    {
        $redacted = [];
        $count    = 0;

        foreach ($values as $key => $value) {
            if (++$count > self::MAX_ITEMS) {
                $redacted['...'] = self::TRUNCATED;

                break;
            }

            $redacted[$key] = is_string($key) && self::namesASecret($key)
                ? RevealedSecret::REDACTED
                : self::redactValue($value, $depth + 1, $trace, $sensitive);
        }

        return $redacted;
    }

    /**
     * The value with every secret in it redacted. In a trace's arguments, a
     * string the sensitive values match is redacted whole and other objects are
     * kept; in a log's normalised values, an exception is scrubbed in place, of
     * the sensitive values too, and other objects are kept.
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @param  bool  $trace
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return mixed
     */
    private static function redactValue(mixed $value, int $depth, bool $trace, SensitiveValues $sensitive): mixed
    {
        return match (true) {
            $value instanceof RevealedSecret,
            $value instanceof \SensitiveParameterValue,
            SensitiveValues::isCodeMessage($value)  => RevealedSecret::REDACTED,
            is_string($value)                       => $trace && $sensitive->matches($value) ? RevealedSecret::REDACTED : self::redactString($value),
            is_array($value)                        => $depth > self::MAX_DEPTH ? self::TRUNCATED : self::redactArray($value, $depth, $trace, $sensitive),
            !$trace && $value instanceof \Throwable => self::scrubbed($value, $sensitive),
            default                                 => $value,
        };
    }

    /**
     * The exception, scrubbed in place, of the sensitive values given too.
     *
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return \Throwable
     */
    private static function scrubbed(\Throwable $throwable, SensitiveValues $sensitive): \Throwable
    {
        ExceptionScrubber::scrubWith($throwable, $sensitive);

        return $throwable;
    }

    /**
     * The array with every object in it normalised, keeping its first thousand
     * entries. A value under a key naming a secret, a code or a destination is
     * kept as it is, since the redaction replaces it whole: no method of an
     * object in it is called, so one that throws when it is turned into its
     * logged form cannot fail the log.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $depth
     * @return array<array-key, mixed>
     */
    private static function normaliseArray(array $values, int $depth): array
    {
        $normalised = [];
        $count      = 0;

        foreach ($values as $key => $value) {
            if (++$count > self::MAX_ITEMS) {
                $normalised['...'] = self::TRUNCATED;

                break;
            }

            $normalised[$key] = is_string($key) && self::namesASecret($key)
                ? $value
                : self::normaliseValue($value, $depth + 1);
        }

        return $normalised;
    }

    /**
     * The value with every object in it normalised, bounded as the redaction
     * is.
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @return mixed
     */
    private static function normaliseValue(mixed $value, int $depth): mixed
    {
        return match (true) {
            is_array($value) => $depth > self::MAX_DEPTH ? self::TRUNCATED : self::normaliseArray($value, $depth),
            !is_object($value),
            $value instanceof RevealedSecret,
            $value instanceof \SensitiveParameterValue,
            SensitiveValues::isCodeMessage($value),
            $value instanceof \Throwable,
            $value instanceof \DateTimeInterface,
            $value instanceof \UnitEnum => $value,
            default                     => self::normaliseObject($value, $depth),
        };
    }

    /**
     * A logged object as what Monolog would log for it, keyed by its class: its
     * array form, its JSON form, its string form or its public properties,
     * themselves normalised.
     *
     * @param  object  $value
     * @param  int  $depth
     * @return mixed
     */
    private static function normaliseObject(object $value, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            return self::TRUNCATED;
        }

        $form = match (true) {
            $value instanceof Arrayable         => $value->toArray(),
            $value instanceof \JsonSerializable => $value->jsonSerialize(),
            $value instanceof \Stringable       => (string) $value,
            default                             => get_object_vars($value),
        };

        return [get_debug_type($value) => self::normaliseValue($form, $depth + 1)];
    }
}
