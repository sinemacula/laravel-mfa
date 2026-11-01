<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

/**
 * Replaces the secrets, codes and full destinations in a set of values, such as
 * a log record's context, with `[redacted]`.
 *
 * A value is redacted when it is a `RevealedSecret` or a
 * `\SensitiveParameterValue`, or when its key names a secret, a code or a
 * destination (`secret`, `totp_secret`, `code`, `codes`, `otp`,
 * `one_time_code`, `recovery_code`, `recovery_codes`, `destination`,
 * `provisioning_uri`, `otpauth_uri`, compared without case, underscores,
 * hyphens or spaces, so `recoveryCodes` counts). An `otpauth://` provisioning
 * URI is redacted wherever it appears in a string. Arrays are walked at any
 * depth, and an exception has its trace scrubbed in place by `TraceScrubber`.
 * Anything else is kept as it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Redactor
{
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
     * The values with every secret, code and full destination in them redacted,
     * at any depth.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    public static function redact(array $values): array
    {
        $redacted = [];

        foreach ($values as $key => $value) {
            $redacted[$key] = is_string($key) && self::namesASecret($key) ? RevealedSecret::REDACTED : self::value($value);
        }

        return $redacted;
    }

    /**
     * The value with every secret in it redacted: a secret value itself,
     * provisioning URIs in a string, and the secrets of an array; an
     * exception's trace is scrubbed in place.
     *
     * @param  mixed  $value
     * @return mixed
     */
    public static function value(mixed $value): mixed
    {
        return match (true) {
            $value instanceof RevealedSecret,
            $value instanceof \SensitiveParameterValue => RevealedSecret::REDACTED,
            $value instanceof \Throwable               => self::scrubbed($value),
            is_array($value)                           => self::redact($value),
            is_string($value)                          => self::redactString($value),
            default                                    => $value,
        };
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
     * The exception, with its trace scrubbed in place.
     *
     * @param  \Throwable  $throwable
     * @return \Throwable
     */
    private static function scrubbed(\Throwable $throwable): \Throwable
    {
        TraceScrubber::scrub($throwable);

        return $throwable;
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
