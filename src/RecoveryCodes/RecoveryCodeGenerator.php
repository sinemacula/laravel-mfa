<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Random\RandomException;

/**
 * Draws distinct, upper-cased codes with `random_int()`, a CSPRNG without
 * modulo bias; a source that keeps repeating itself is refused, not looped on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeGenerator
{
    /** @var int Draws allowed per code before the source of randomness is refused. */
    public const int DRAWS_PER_CODE = 100;

    /** @var \Closure(int, int): int Defaults to `random_int(...)`. */
    private \Closure $randomInt;

    /**
     * Tests pass a deterministic `$randomInt` to drive known draws.
     *
     * @param  ?callable(int, int): int  $randomInt
     */
    public function __construct(?callable $randomInt = null)
    {
        $this->randomInt = $randomInt === null ? random_int(...) : $randomInt(...);
    }

    /**
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
