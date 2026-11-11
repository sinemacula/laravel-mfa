<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model on the `secondary` connection, refused at boot and before any
 * state change unless that is the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecondaryConnectionFactor extends Factor
{
    /** @var string|\UnitEnum|null */
    protected $connection = 'secondary';
}
