<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Illuminate\Database\Eloquent\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;

/**
 * Unit tests for `LockedFactors`: which factors keep state of their own, how a
 * factor is found among the locked ones by its id, and which ids are usable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LockedFactors::class)]
final class LockedFactorsTest extends TestCase
{
    /**
     * Only an Eloquent factor model keeps state of its own.
     *
     * @return void
     */
    public function testOnlyAnEloquentFactorKeepsState(): void
    {
        self::assertTrue(LockedFactors::keepsState($this->given($this->factor('stored'))));
        self::assertFalse(LockedFactors::keepsState($this->given(new InMemoryFactor)));
        self::assertFalse(LockedFactors::keepsState($this->given(null)));
    }

    /**
     * A factor is found as the locked instance with the same id, not the one it
     * was looked up with.
     *
     * @return void
     */
    public function testAFactorIsFoundAsTheLockedInstance(): void
    {
        $locked = $this->factor('second');
        $found  = LockedFactors::find($this->factor('second'), new Collection([$this->factor('first'), $locked]));

        self::assertSame($locked, $found);
    }

    /**
     * Nothing is found for a factor that keeps no state, has no usable id, or
     * is not among the locked ones.
     *
     * @return void
     */
    public function testNothingIsFoundWithoutAStoredMatch(): void
    {
        $factors = new Collection([$this->factor('stored'), $this->factor('')]);

        self::assertNull(LockedFactors::find(null, $factors));
        self::assertNull(LockedFactors::find(new InMemoryFactor(identifier: 'stored'), $factors));
        self::assertNull(LockedFactors::find($this->factor(''), $factors));
        self::assertNull(LockedFactors::find($this->factor('other'), $factors));
    }

    /**
     * The ids a factor is matched by.
     *
     * @return iterable<string, array{0: mixed, 1: ?string}>
     */
    public static function ids(): iterable
    {
        yield 'a string' => ['01jd5g', '01jd5g'];
        yield 'an integer' => [7, '7'];
        yield 'an empty string' => ['', null];
        yield 'neither' => [7.5, null];
    }

    /**
     * A factor's id is usable as a non-empty string or an integer, as a string.
     *
     * @param  mixed  $id
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('ids')]
    public function testAnIdIsUsableAsAStringOrAnInteger(mixed $id, ?string $expected): void
    {
        self::assertSame($expected, LockedFactors::idOf(new InMemoryFactor(identifier: $id)));
    }

    /**
     * The factor as the contract an attempt names it by.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function given(?FactorContract $factor): ?FactorContract
    {
        return $factor;
    }

    /**
     * An unsaved factor model with the given id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factor(string $id): Factor
    {
        $factor = new Factor;

        $factor->setAttribute($factor->getKeyName(), $id);

        return $factor;
    }
}
