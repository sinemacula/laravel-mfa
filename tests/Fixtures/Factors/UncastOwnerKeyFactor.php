<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model that leaves its owner key uncast, as an application's own
 * model may, so the key reads back as whatever type was set on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UncastOwnerKeyFactor extends Factor
{
    /**
     * The shipped model's casts, without the owner key's.
     *
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
