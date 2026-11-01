<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Contracts\Support\Arrayable;

/**
 * Replaces the secrets, codes and full destinations in a set of values, such as
 * a log record's context or a trace frame's arguments, with `[redacted]`.
 *
 * A value is redacted when it is a `RevealedSecret` or a
 * `\SensitiveParameterValue`, or when its key names a secret, a code or a
 * destination (`secret`, `totp_secret`, `code`, `codes`, `otp`,
 * `one_time_code`, `recovery_code`, `recovery_codes`, `destination`,
 * `provisioning_uri`, `otpauth_uri`, compared without case, underscores,
 * hyphens or spaces, so `recoveryCodes` counts). An `otpauth://` provisioning
 * URI is redacted wherever it appears in a string.
 *
 * In a log's values, an exception is scrubbed in place by `ExceptionScrubber`,
 * a date or an enum is kept, and any other object is turned into what Monolog
 * would log for it, keyed by its class, before it is redacted, so a secret held
 * in an object cannot slip past. In a trace's arguments, objects are kept as
 * they are, and a string that is, or contains, a value the package passed on is
 * redacted too.
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

    /** @var int The length from which a passed-on value is redacted wherever a string contains it. */
    private const int CONTAINED_LENGTH = 6;

    /** @var list<string> The keys whose values are redacted, without case, underscores, hyphens or spaces. */
    private const array KEYS = [
        'code',
        'codes',
        'destination',
        'onetimecode',
        'otp',
        'otpauthuri',
        'provisioninguri',
        'recoverycode',
        'recoverycodes',
        'secret',
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
     * redacted.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    public static function redact(array $values): array
    {
        return self::redactArray($values, 0, null);
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
        return self::redactValue($value, 0, null);
    }

    /**
     * A trace frame's arguments with every secret in them redacted, and every
     * string that is a value the package passed on, or contains one of six
     * characters or more. Objects are kept as they are.
     *
     * @param  array<array-key, mixed>  $arguments
     * @param  list<string>  $passed
     * @return array<array-key, mixed>
     */
    public static function arguments(array $arguments, array $passed = []): array
    {
        return self::redactArray($arguments, 0, $passed);
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
     * The array with every secret in it redacted, keeping its first thousand
     * entries.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $depth
     * @param  ?list<string>  $passed
     * @return array<array-key, mixed>
     */
    private static function redactArray(array $values, int $depth, ?array $passed): array
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
                : self::redactValue($value, $depth + 1, $passed);
        }

        return $redacted;
    }

    /**
     * The value with every secret in it redacted. The values passed on are
     * given for a trace's arguments, whose objects are kept, and are null for a
     * log's values, whose exceptions are scrubbed in place and whose other
     * objects, dates and enums aside, are redacted in the form Monolog logs.
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @param  ?list<string>  $passed
     * @return mixed
     */
    private static function redactValue(mixed $value, int $depth, ?array $passed): mixed
    {
        return match (true) {
            $value instanceof RevealedSecret,
            $value instanceof \SensitiveParameterValue => RevealedSecret::REDACTED,
            is_string($value)                          => self::redactPassedOn($value, $passed ?? []),
            is_array($value)                           => $depth > self::MAX_DEPTH ? self::TRUNCATED : self::redactArray($value, $depth, $passed),
            $passed !== null,
            !is_object($value),
            $value instanceof \DateTimeInterface,
            $value instanceof \UnitEnum  => $value,
            $value instanceof \Throwable => self::scrubbed($value),
            default                      => self::redactObject($value, $depth),
        };
    }

    /**
     * The string redacted whole when it is, or contains, a value passed on;
     * otherwise with every provisioning URI in it redacted.
     *
     * @param  string  $value
     * @param  list<string>  $passed
     * @return string
     */
    private static function redactPassedOn(string $value, array $passed): string
    {
        foreach ($passed as $known) {
            if ($value === $known || (strlen($known) >= self::CONTAINED_LENGTH && str_contains($value, $known))) {
                return RevealedSecret::REDACTED;
            }
        }

        return self::redactString($value);
    }

    /**
     * The exception, scrubbed in place.
     *
     * @param  \Throwable  $throwable
     * @return \Throwable
     */
    private static function scrubbed(\Throwable $throwable): \Throwable
    {
        ExceptionScrubber::scrub($throwable);

        return $throwable;
    }

    /**
     * A logged object as what Monolog would log for it, keyed by its class,
     * with every secret in it redacted: its array form, its JSON form, its
     * string form or its public properties.
     *
     * @param  object  $value
     * @param  int  $depth
     * @return mixed
     */
    private static function redactObject(object $value, int $depth): mixed
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

        return [get_debug_type($value) => self::redactValue($form, $depth + 1, null)];
    }

    /**
     * Whether the key names a secret, a code or a destination.
     *
     * @param  string  $key
     * @return bool
     */
    private static function namesASecret(string $key): bool
    {
        return in_array(strtolower(str_replace(['_', '-', ' '], '', $key)), self::KEYS, true);
    }
}
