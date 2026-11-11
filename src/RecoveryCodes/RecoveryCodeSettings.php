<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The `mfa.recovery_codes` settings, read and validated on every call; a value
 * out of bounds fails closed naming the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeSettings
{
    /** @var int Least entropy of one code in bits, measured after normalisation. */
    public const int MINIMUM_ENTROPY_BITS = 40;

    /** @var int Longest a code may be, in characters. */
    public const int MAXIMUM_LENGTH = 64;

    /** @var string Prefix of every recovery code setting's key. */
    private const string PREFIX = 'mfa.recovery_codes.';

    /** @var string Digits and capitals without the look-alikes 0, 1, I and O. */
    private const string ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

    /** @var int Default low-count threshold, capped at the set's size. */
    private const int LOW_COUNT = 3;

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value per setting. */
    private const array NUMBERS = [
        'count'  => [10, 1, 50],
        'length' => [13, 1, self::MAXIMUM_LENGTH],
    ];

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call so changed settings apply. */
        private Repository $config,
    ) {}

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function count(): int
    {
        return $this->number('count');
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function length(): int
    {
        return $this->number('length');
    }

    /**
     * No spaces, hyphens or case-folded repeats, so a uniform draw stays
     * uniform over the symbols a normalised code can hold.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function alphabet(): string
    {
        $alphabet = $this->config->get(self::PREFIX . 'alphabet', self::ALPHABET);

        if (!is_string($alphabet) || preg_match('/^[\x21-\x2C\x2E-\x7E]{2,}$/', $alphabet) !== 1 || self::symbols($alphabet) !== strlen($alphabet)) {
            $message = '%salphabet must be at least two printable ASCII characters, none repeated ignoring case, without spaces or hyphens.';

            throw new \InvalidArgumentException(sprintf($message, self::PREFIX));
        }

        return $alphabet;
    }

    /**
     * Unused codes at or below which the set is running low; 0 never warns.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function lowCount(): int
    {
        $count = $this->count();

        return IntegerSetting::read($this->config, self::PREFIX . 'low_count', min(self::LOW_COUNT, $count), 0, $count);
    }

    /**
     * Entropy of one code in bits, measured after normalisation.
     *
     * @return float
     *
     * @throws \InvalidArgumentException
     */
    public function entropyBits(): float
    {
        return $this->length() * log(strlen($this->alphabet()), 2);
    }

    /**
     * Fail on the first setting out of bounds, or on codes below the least
     * entropy.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->lowCount();

        if ($this->entropyBits() < self::MINIMUM_ENTROPY_BITS) {
            $message = '%1$slength and %1$salphabet must give each code at least %2$d bits of entropy after normalisation.';

            throw new \InvalidArgumentException(sprintf($message, self::PREFIX, self::MINIMUM_ENTROPY_BITS));
        }
    }

    /**
     * @param  string  $alphabet
     * @return int
     */
    private static function symbols(string $alphabet): int
    {
        return count(count_chars(strtoupper($alphabet), 1));
    }

    /**
     * @param  string  $key
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $key): int
    {
        [$default, $least, $most] = self::NUMBERS[$key];

        return IntegerSetting::read($this->config, self::PREFIX . $key, $default, $least, $most);
    }
}
