<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Factor subclass stored under an auto-incrementing integer key.
 *
 * Stands in for an application's own factor model that does not use the shipped
 * model's ULIDs, so its factors are named by integers. Its table is the one
 * `mfa.factor.table` names, `test_integer_keyed_factors` in the tests that use
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerKeyedFactor extends Factor
{
    /**
     * Generate no unique identifiers: the database assigns the key.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return [];
    }
}
