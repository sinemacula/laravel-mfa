<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;

/**
 * A `DecodedRouteKeyFactor` keyed by an auto-incrementing integer, on
 * `test_integer_keyed_factors`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour, sineMaculaLaravel.modelBehaviour
 */
final class IntegerKeyedDecodedRouteKeyFactor extends DecodedRouteKeyFactorBase
{
    use ResolvesFactorRouteBinding;

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
