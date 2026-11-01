<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * The parameters a TOTP factor's codes are made with (RFC 6238): the HMAC
 * algorithm, the number of digits and the period of a time step. A factor keeps
 * the parameters it was enrolled with, so it works the same way in every
 * application and after the configuration changes.
 *
 * A code is the HOTP value (RFC 4226 §5.3) of the time step: the HMAC of the
 * step as an 8-byte big-endian counter, dynamically truncated to 31 bits and
 * reduced to the number of digits, zero-padded on the left. Values outside the
 * bounds the configuration allows are refused, here as when they are read.
 *
 * `TotpDriver::parameters()` returns the parameters new enrolments use, for a
 * factor that is not an Eloquent model to store with its secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TotpParameters
{
    /** @var list<string> The HMAC algorithms a TOTP factor may use, as RFC 6238 names them. */
    public const array ALGORITHMS = ['sha1', 'sha256', 'sha512'];

    /** @var int The fewest digits a code may have. */
    public const int MIN_DIGITS = 6;

    /** @var int The most digits a code may have. */
    public const int MAX_DIGITS = 8;

    /** @var int The shortest time step, in seconds. */
    public const int MIN_PERIOD = 15;

    /** @var int The longest time step, in seconds. */
    public const int MAX_PERIOD = 120;

    /**
     * Constructor.
     *
     * @param  string  $algorithm
     * @param  int  $digits
     * @param  int  $period
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The HMAC algorithm: `sha1`, `sha256` or `sha512`. */
        public string $algorithm,

        /** The number of digits in a code. */
        public int $digits,

        /** The length of a time step, in seconds. */
        public int $period,
    ) {
        if (!self::allows($algorithm, $digits, $period)) {
            $message = sprintf('TOTP parameters must name one of %s, ', implode(', ', self::ALGORITHMS))
                . sprintf('%d to %d digits and a period of %d to %d seconds.', self::MIN_DIGITS, self::MAX_DIGITS, self::MIN_PERIOD, self::MAX_PERIOD);

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * The parameters the factor was enrolled with, or `null` when it holds
     * none, or holds values outside the bounds, so it verifies nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?self
     */
    public static function fromFactor(Factor $factor): ?self
    {
        $algorithm = $factor->getTotpAlgorithm();
        $digits    = $factor->getTotpDigits();
        $period    = $factor->getTotpPeriod();

        if ($algorithm === null || $digits === null || $period === null || !self::allows($algorithm, $digits, $period)) {
            return null;
        }

        return new self($algorithm, $digits, $period);
    }

    /**
     * How many random bytes a new secret has: the length of the algorithm's
     * output, which RFC 6238 recommends for the key and is never under 160
     * bits.
     *
     * @return int
     */
    public function secretLength(): int
    {
        return match ($this->algorithm) {
            'sha256' => 32,
            'sha512' => 64,
            default  => 20,
        };
    }

    /**
     * The time step the moment falls in: whole periods since the Unix epoch.
     *
     * @param  int  $timestamp
     * @return int
     */
    public function stepAt(int $timestamp): int
    {
        return intdiv($timestamp, $this->period);
    }

    /**
     * The code for the time step, made with the key.
     *
     * @param  string  $key
     * @param  int  $step
     * @return string
     */
    public function code(#[\SensitiveParameter] string $key, int $step): string
    {
        $hash   = hash_hmac($this->algorithm, pack('J', $step), $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $value = (ord($hash[$offset]) & 0x7F) << 24
            | ord($hash[$offset + 1])         << 16
            | ord($hash[$offset + 2])         << 8
            | ord($hash[$offset + 3]);

        return str_pad((string) ($value % (int) (10 ** $this->digits)), $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * Whether the values are within the bounds.
     *
     * @param  string  $algorithm
     * @param  int  $digits
     * @param  int  $period
     * @return bool
     */
    private static function allows(string $algorithm, int $digits, int $period): bool
    {
        if (!in_array($algorithm, self::ALGORITHMS, true)) {
            return false;
        }

        return self::isWithin($digits, self::MIN_DIGITS, self::MAX_DIGITS)
            && self::isWithin($period, self::MIN_PERIOD, self::MAX_PERIOD);
    }

    /**
     * Whether the value lies between the bounds, inclusive.
     *
     * @param  int  $value
     * @param  int  $min
     * @param  int  $max
     * @return bool
     */
    private static function isWithin(int $value, int $min, int $max): bool
    {
        return $value >= $min && $value <= $max;
    }
}
