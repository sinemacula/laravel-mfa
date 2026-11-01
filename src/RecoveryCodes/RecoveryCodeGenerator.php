<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Random\RandomException;

/**
 * Draws the codes of a recovery code set.
 *
 * Each character is drawn from the alphabet with `random_int()`, PHP's
 * cryptographically secure generator, which samples uniformly without modulo
 * bias, and a code is upper-cased as it is drawn, the form its hash is made
 * from and a submitted code is normalised to (see `RecoveryCodeNormalizer`). A
 * code already in the set is drawn again, so the set's codes are distinct. The
 * settings (see `RecoveryCodeSettings`) give every code at least 40 bits, so a
 * second draw is all but never needed; a source of randomness that keeps
 * repeating itself is refused rather than drawn from for ever.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeGenerator
{
    /** @var int How many draws each code of a set may take before the source of randomness is refused. */
    public const int DRAWS_PER_CODE = 100;

    /** @var \Closure(int, int): int The source of randomness: `random_int(...)` by default. */
    private \Closure $randomInt;

    /**
     * Constructor.
     *
     * `$randomInt` is the source of randomness, `random_int(...)` when none is
     * given; tests substitute a deterministic one to drive known draws.
     *
     * @param  ?callable(int, int): int  $randomInt
     */
    public function __construct(?callable $randomInt = null)
    {
        $this->randomInt = $randomInt === null ? random_int(...) : $randomInt(...);
    }

    /**
     * Draw a set of distinct codes, each of the given length from the given
     * alphabet, upper-cased, in the order they were drawn.
     *
     * @param  int  $count
     * @param  int  $length
     * @param  string  $alphabet
     * @return list<string>
     *
     * @throws \Random\RandomException
     */
    public function generate(int $count, int $length, string $alphabet): array
    {
        $codes = [];
        $draws = 0;

        while (count($codes) < $count) {

            if (++$draws > $count * self::DRAWS_PER_CODE) {
                throw new RandomException(sprintf('No set of %d distinct recovery codes could be drawn: the source of randomness keeps repeating itself.', $count));
            }

            $code = strtoupper($this->draw($length, $alphabet));

            if (in_array($code, $codes, true)) {
                continue;
            }

            $codes[] = $code;
        }

        return $codes;
    }

    /**
     * Draw one code of the given length from the alphabet.
     *
     * @param  int  $length
     * @param  string  $alphabet
     * @return string
     */
    private function draw(int $length, string $alphabet): string
    {
        $last = strlen($alphabet) - 1;
        $code = '';

        for ($index = 0; $index < $length; $index++) {
            $code .= $alphabet[($this->randomInt)(0, $last)];
        }

        return $code;
    }
}
