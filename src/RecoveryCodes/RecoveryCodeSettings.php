<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The recovery code settings in `mfa.recovery_codes`, read on every call and
 * validated as they are read: how many codes a set holds, how long each is and
 * the alphabet it is drawn from, and how few remaining codes count as running
 * low. A value outside its bounds fails closed with an
 * `InvalidArgumentException` naming the key; the package checks them when it
 * boots and `mfa:check` reports them.
 *
 * A code is normalised before it is checked (case folded, spaces and hyphens
 * removed), so its entropy is measured on what is left: the length times the
 * bits of each character. The alphabet is printable ASCII without spaces or
 * hyphens, which normalisation would remove, and no character appears in it
 * twice once case is folded, so each character a code is drawn from is a
 * distinct symbol drawn with equal probability. A code must carry at least
 * `MINIMUM_ENTROPY_BITS`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeSettings
{
    /** @var int The least entropy of one code, in bits, measured after normalisation. */
    public const int MINIMUM_ENTROPY_BITS = 40;

    /** @var int The longest a code may be, in characters. */
    public const int MAXIMUM_LENGTH = 64;

    /** @var string Prefix of every recovery code setting's key. */
    private const string PREFIX = 'mfa.recovery_codes.';

    /** @var string The alphabet when none is configured: digits and capitals, without 0, 1, I and O. */
    private const string ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

    /** @var int The low-count threshold when none is configured and the set holds at least as many codes. */
    private const int LOW_COUNT = 3;

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each other numeric setting. */
    private const array NUMBERS = [
        'count'  => [10, 1, 50],
        'length' => [13, 1, self::MAXIMUM_LENGTH],
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * How many codes a set holds, 1 to 50.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function count(): int
    {
        return $this->number('count');
    }

    /**
     * How many characters each code has, 1 to 64, and enough with the alphabet
     * for the least entropy.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function length(): int
    {
        return $this->number('length');
    }

    /**
     * The characters codes are drawn from: at least two, printable ASCII, no
     * spaces or hyphens, and none appearing twice once case is folded, so a
     * uniform draw over the alphabet is a uniform draw over the symbols a
     * normalised code can hold.
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
     * How few unused codes count as running low, from 0 (never) to the set's
     * size; 3 by default, or the set's size when the set is smaller.
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
     * The entropy of one code, in bits, measured after normalisation.
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
     * Read every setting, failing closed on the first that is out of bounds,
     * then refuse a length and alphabet whose codes carry less than the least
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
     * The number of distinct characters in the alphabet once case is folded.
     *
     * @param  string  $alphabet
     * @return int
     */
    private static function symbols(string $alphabet): int
    {
        return count(count_chars(strtoupper($alphabet), 1));
    }

    /**
     * Read a numeric setting from its least to its greatest value.
     *
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
