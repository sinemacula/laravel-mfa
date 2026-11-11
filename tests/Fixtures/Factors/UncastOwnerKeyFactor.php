<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Leaves its owner key uncast, so the key reads back as whatever type was set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UncastOwnerKeyFactor extends Factor
{
    /**
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        $casts = parent::casts();

        unset($casts['authenticatable_id']);

        return $casts;
    }
}
