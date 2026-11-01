<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Factor subclass bound to the `secondary` database connection.
 *
 * Stands in for a consumer's factor model that names a connection of its own:
 * accepted when that connection is the storage connection, refused when the
 * package boots, and before any factor state change, otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecondaryConnectionFactor extends Factor
{
    /** @var string|\UnitEnum|null Connection name this subclass routes all I/O through. */
    protected $connection = 'secondary';
}
