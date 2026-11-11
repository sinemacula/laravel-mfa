<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGenerator;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeGenerator::class)]
final class RecoveryCodeGeneratorTest extends TestCase
{
    /** @var string The shipped alphabet. */
    private const string ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDrawsDistinctCodesFromTheAlphabet(): void
    {
        $codes = (new RecoveryCodeGenerator)->generate(50, 12, self::ALPHABET);

        self::assertCount(50, $codes);
        self::assertSame($codes, array_values(array_unique($codes)));

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[' . self::ALPHABET . ']{12}$/', $code);
        }
    }

    /**
     * Each draw asks for an index across the whole alphabet, and the code is
     * upper-cased.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEveryCharacterOfTheAlphabetCanBeDrawn(): void
    {
        $asked = [];
        $next  = 0;

        $generator = new RecoveryCodeGenerator(static function (int $min, int $max) use (&$asked, &$next): int {
            $asked[] = [$min, $max];

            return $next++ % ($max + 1);
        });

        self::assertSame(['ABCDEFGHJK'], $generator->generate(1, 10, 'abcdefghjk'));
        self::assertSame(array_fill(0, 10, [0, 9]), $asked);
    }

    /**
     * The set still holds the size asked for, every code distinct, in the order
     * drawn.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARepeatedCodeIsDrawnAgain(): void
    {
        $draws = [0, 0, 0, 0, 1, 1];

        $generator = new RecoveryCodeGenerator(static function () use (&$draws): int {
            return (int) array_shift($draws);
        });

        self::assertSame(['AA', 'BB'], $generator->generate(2, 2, 'AB'));
        self::assertSame([], $draws);
    }

    /**
     * Once each code of the set has had its draws, rather than drawing for
     * ever.
     *
     * @return void
     */
    public function testASourceThatKeepsRepeatingItselfIsRefused(): void
    {
        $calls = 0;

        $generator = new RecoveryCodeGenerator(static function () use (&$calls): int {
            $calls++;

            return 0;
        });

        try {
            $generator->generate(2, 1, 'AB');
            self::fail('A source that keeps repeating itself was expected to be refused.');
        } catch (RandomException $exception) {
            self::assertSame('No set of 2 distinct recovery codes could be drawn: the source of randomness keeps repeating itself.', $exception->getMessage());
        }

        self::assertSame(2 * RecoveryCodeGenerator::DRAWS_PER_CODE, $calls);
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEmptySetDrawsNothing(): void
    {
        $generator = new RecoveryCodeGenerator(static function (): int {
            self::fail('Nothing should be drawn.');
        });

        self::assertSame([], $generator->generate(0, 12, self::ALPHABET));
    }
}
