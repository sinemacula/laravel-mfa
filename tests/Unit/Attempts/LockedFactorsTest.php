<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\FactorSets;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LockedFactors::class)]
final class LockedFactorsTest extends TestCase
{
    /**
     * Not a factor that is no model, nor a model that is a factor but not an
     * Eloquent one.
     *
     * @return void
     */
    public function testOnlyAnEloquentFactorKeepsState(): void
    {
        self::assertTrue(LockedFactors::keepsState($this->given($this->factor('stored'))));
        self::assertFalse(LockedFactors::keepsState($this->given(new InMemoryFactor)));
        self::assertFalse(LockedFactors::keepsState($this->given(null)));
        self::assertFalse(LockedFactors::keepsState($this->given(new class extends Model implements FactorContract {
            use ActsAsFactor;
        })));
    }

    /**
     * Not the one it was looked up with.
     *
     * @return void
     */
    public function testAFactorIsFoundAsTheLockedInstance(): void
    {
        $locked = $this->factor('second');
        $found  = LockedFactors::find($this->factor('second'), FactorSets::of($this->factor('first'), $locked));

        self::assertSame($locked, $found);
    }

    /**
     * For a factor that keeps no state, has no usable id, or is not among the
     * locked ones.
     *
     * @return void
     */
    public function testNothingIsFoundWithoutAStoredMatch(): void
    {
        $factors = FactorSets::of($this->factor('stored'), $this->factor(''));

        self::assertNull(LockedFactors::find(null, $factors));
        self::assertNull(LockedFactors::find(new InMemoryFactor(identifier: 'stored'), $factors));
        self::assertNull(LockedFactors::find($this->factor(''), $factors));
        self::assertNull(LockedFactors::find($this->factor('other'), $factors));
    }

    /**
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
     * As a non-empty string or an integer, given back as a string.
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
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function given(?FactorContract $factor): ?FactorContract
    {
        return $factor;
    }

    /**
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
