<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * A TOTP factor's parameters, kept from enrolment so a configuration change
 * does not alter existing factors.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TotpParameters
{
    /** @var list<string> As RFC 6238 names them. */
    public const array ALGORITHMS = ['sha1', 'sha256', 'sha512'];

    /** @var int */
    public const int MIN_DIGITS = 6;

    /** @var int */
    public const int MAX_DIGITS = 8;

    /** @var int In seconds. */
    public const int MIN_PERIOD = 15;

    /** @var int In seconds. */
    public const int MAX_PERIOD = 120;

    /**
     * @param  string  $algorithm
     * @param  int  $digits
     * @param  int  $period
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** One of `ALGORITHMS`. */
        public string $algorithm,

        /** Digits in a code. */
        public int $digits,

        /** Time step, in seconds. */
        public int $period,
    ) {
        if (!self::allows($algorithm, $digits, $period)) {
            $message = sprintf('TOTP parameters must name one of %s, ', implode(', ', self::ALGORITHMS))
                . sprintf('%d to %d digits and a period of %d to %d seconds.', self::MIN_DIGITS, self::MAX_DIGITS, self::MIN_PERIOD, self::MAX_PERIOD);

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * Null when the factor holds none or holds out-of-bounds values, so it
     * verifies nothing.
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
     * The algorithm's output length, as RFC 6238 recommends for the key.
     *
     * @return 20|32|64
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
     * @param  int  $timestamp
     * @return int
     */
    public function stepAt(int $timestamp): int
    {
        return intdiv($timestamp, $this->period);
    }

    /**
     * The HOTP value (RFC 4226 section 5.3) of the step.
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
