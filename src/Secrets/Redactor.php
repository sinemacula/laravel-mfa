<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Contracts\Support\Arrayable;

/**
 * Replaces secrets, codes, full destinations and values under keys naming one
 * with `[redacted]` in log values or trace arguments.
 *
 * The walk is bounded in depth and width so a recursive or very large value
 * cannot exhaust memory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Redactor
{
    /** @var string Replaces what the walk does not reach. */
    public const string TRUNCATED = '[truncated]';

    /** @var string Replaces the form of an object that throws when asked for one. */
    public const string UNSERIALIZABLE = '[unserializable]';

    /** @var int */
    public const int MAX_DEPTH = 10;

    /** @var int */
    private const int MAX_ITEMS = 1000;

    /** @var list<string> Compared without case, underscores, hyphens or spaces. */
    private const array KEYS = [
        'address',
        'code',
        'codes',
        'destination',
        'email',
        'enrollmentgrant',
        'grant',
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

    /** @var string An `otpauth://` URI carries the TOTP secret. */
    private const string PROVISIONING_URI = '~otpauth(?:-migration)?://\S*~i';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Expects values already passed through `normalize()`.
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return array<array-key, mixed>
     */
    public static function redactNormalized(array $values, SensitiveValues $sensitive): array
    {
        return self::redactArray($values, 0, false, $sensitive);
    }

    /**
     * Turns each object into what Monolog would log for it, so a secret held in
     * an object cannot slip past the redaction.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    public static function normalize(array $values): array
    {
        return self::normalizeArray($values, 0);
    }

    /**
     * Objects other than code messages are kept as they are.
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
     * @param  string  $message
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return string
     */
    public static function redactMessage(string $message, SensitiveValues $values): string
    {
        return self::redactString($values->redactIn($message));
    }

    /**
     * @param  string  $value
     * @return string
     */
    public static function redactString(string $value): string
    {
        return preg_replace(self::PROVISIONING_URI, RevealedSecret::REDACTED, $value) ?? RevealedSecret::REDACTED;
    }

    /**
     * @param  string  $key
     * @return bool
     */
    public static function namesASecret(string $key): bool
    {
        return in_array(strtolower(str_replace(['_', '-', ' '], '', $key)), self::KEYS, true);
    }

    /**
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
     * In a log's values, an exception is scrubbed in place.
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
     * Secret-keyed values are left untouched, as redaction replaces them whole
     * and an object there that throws must not fail the log.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $depth
     * @return array<array-key, mixed>
     */
    private static function normalizeArray(array $values, int $depth): array
    {
        $normalized = [];
        $count      = 0;

        foreach ($values as $key => $value) {
            if (++$count > self::MAX_ITEMS) {
                $normalized['...'] = self::TRUNCATED;

                break;
            }

            $normalized[$key] = is_string($key) && self::namesASecret($key)
                ? $value
                : self::normalizeValue($value, $depth + 1);
        }

        return $normalized;
    }

    /**
     * A `JsonSerializable` exception or enum is normalised, as Monolog logs its
     * JSON form.
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @return mixed
     */
    private static function normalizeValue(mixed $value, int $depth): mixed
    {
        return match (true) {
            is_array($value)              => $depth > self::MAX_DEPTH ? self::TRUNCATED : self::normalizeArray($value, $depth),
            self::givesItsOwnForm($value) => self::normalizeObject($value, $depth),
            !is_object($value),
            $value instanceof RevealedSecret,
            $value instanceof \SensitiveParameterValue,
            SensitiveValues::isCodeMessage($value),
            $value instanceof \Throwable,
            $value instanceof \DateTimeInterface,
            $value instanceof \UnitEnum => $value,
            default                     => self::normalizeObject($value, $depth),
        };
    }

    /**
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true (\JsonSerializable&\Throwable)|(\JsonSerializable&\UnitEnum) $value
     */
    private static function givesItsOwnForm(mixed $value): bool
    {
        return $value instanceof \JsonSerializable && ($value instanceof \Throwable || $value instanceof \UnitEnum);
    }

    /**
     * Keyed by class. An object that throws is logged as its class alone, so
     * the line is still written and nothing it holds is read another way.
     *
     * @param  object  $value
     * @param  int  $depth
     * @return mixed
     */
    private static function normalizeObject(object $value, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            return self::TRUNCATED;
        }

        // Any form may throw; PHPStan cannot see it
        try {
            $form = match (true) {
                $value instanceof Arrayable         => $value->toArray(),
                $value instanceof \JsonSerializable => $value->jsonSerialize(),
                $value instanceof \Stringable       => (string) $value,
                default                             => get_object_vars($value),
            };
        } catch (\Throwable) { // @phpstan-ignore catch.neverThrown
            return [get_debug_type($value) => self::UNSERIALIZABLE];
        }

        return [get_debug_type($value) => self::normalizeValue($form, $depth + 1)];
    }
}
