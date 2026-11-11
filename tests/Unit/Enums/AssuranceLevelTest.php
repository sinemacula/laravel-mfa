<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssuranceLevel::class)]
final class AssuranceLevelTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testLevelsAreTheStableValues(): void
    {
        self::assertSame([
            'AAL1'         => 'aal1',
            'AAL2'         => 'aal2',
            'AAL3'         => 'aal3',
            'UNCLASSIFIED' => 'unclassified',
        ], array_column(AssuranceLevel::cases(), 'value', 'name'));
    }

    /**
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\AssuranceLevel, \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, bool}>
     */
    public static function provideLevelsAgainstMinimums(): iterable
    {
        yield 'aal1 meets aal1' => [AssuranceLevel::AAL1, AssuranceLevel::AAL1, true];
        yield 'aal1 misses aal2' => [AssuranceLevel::AAL1, AssuranceLevel::AAL2, false];
        yield 'aal1 misses aal3' => [AssuranceLevel::AAL1, AssuranceLevel::AAL3, false];
        yield 'aal2 meets aal1' => [AssuranceLevel::AAL2, AssuranceLevel::AAL1, true];
        yield 'aal2 meets aal2' => [AssuranceLevel::AAL2, AssuranceLevel::AAL2, true];
        yield 'aal2 misses aal3' => [AssuranceLevel::AAL2, AssuranceLevel::AAL3, false];
        yield 'aal3 meets aal1' => [AssuranceLevel::AAL3, AssuranceLevel::AAL1, true];
        yield 'aal3 meets aal2' => [AssuranceLevel::AAL3, AssuranceLevel::AAL2, true];
        yield 'aal3 meets aal3' => [AssuranceLevel::AAL3, AssuranceLevel::AAL3, true];
        yield 'unclassified misses aal1' => [AssuranceLevel::UNCLASSIFIED, AssuranceLevel::AAL1, false];
        yield 'unclassified misses aal2' => [AssuranceLevel::UNCLASSIFIED, AssuranceLevel::AAL2, false];
        yield 'unclassified misses aal3' => [AssuranceLevel::UNCLASSIFIED, AssuranceLevel::AAL3, false];
        yield 'unclassified misses unclassified' => [AssuranceLevel::UNCLASSIFIED, AssuranceLevel::UNCLASSIFIED, false];
        yield 'aal1 meets no minimum' => [AssuranceLevel::AAL1, AssuranceLevel::UNCLASSIFIED, true];
        yield 'aal3 meets no minimum' => [AssuranceLevel::AAL3, AssuranceLevel::UNCLASSIFIED, true];
    }

    /**
     * Unclassified minimums included; an unclassified level meets none.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $minimum
     * @param  bool  $meets
     * @return void
     */
    #[DataProvider('provideLevelsAgainstMinimums')]
    public function testALevelMeetsTheMinimumsAtOrBelowIt(AssuranceLevel $level, AssuranceLevel $minimum, bool $meets): void
    {
        self::assertSame($meets, $level->meets($minimum));
    }
}
