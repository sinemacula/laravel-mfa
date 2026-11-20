<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * An integer-keyed factor model declaring Laravel's `integer` key type alias,
 * on `test_integer_keyed_factors`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerAliasKeyedFactor extends Factor
{
    /** @var string */
    protected $keyType = 'integer';

    /**
     * The database assigns the key.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return [];
    }
}
