<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model that casts its status to the enum, as an application's own
 * model may, so a stored value the enum does not know throws Laravel's
 * `ValueError` when it is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnumStatusFactor extends Factor
{
    /**
     * The attributes that should be cast: the shipped ones, with the status as
     * the enum.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [...parent::casts(), 'status' => FactorStatus::class];
    }
}
