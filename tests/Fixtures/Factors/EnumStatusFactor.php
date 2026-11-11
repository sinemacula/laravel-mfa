<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Casts its status to the enum, so an unknown stored value throws a
 * `ValueError` when read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnumStatusFactor extends Factor
{
    /**
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [...parent::casts(), 'status' => FactorStatus::class];
    }
}
