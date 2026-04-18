<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Factor subclass bound to the `secondary` database connection.
 *
 * Used by `BackupCodeRotationConnectionTest` to prove the manager opens the
 * backup-code rotation transaction on the factor model's own connection. If
 * the outer `transaction()` call were still taken against the default
 * `ConnectionInterface` binding, the rotation's atomicity guarantee would not
 * extend to a non-default connection — which is exactly the configuration
 * path this fixture exercises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SecondaryConnectionFactor extends Factor
{
    /** @var string|\UnitEnum|null Connection name this subclass routes all I/O through. */
    protected $connection = 'secondary';
}
