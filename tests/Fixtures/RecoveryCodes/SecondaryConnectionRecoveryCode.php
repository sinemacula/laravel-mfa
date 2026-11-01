<?php

declare(strict_types = 1);

namespace Tests\Fixtures\RecoveryCodes;

use SineMacula\Laravel\Mfa\Models\RecoveryCode;

/**
 * Recovery code subclass bound to the `secondary` database connection, standing
 * in for an application's model that names a connection of its own: refused
 * when the package boots unless that connection is the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecondaryConnectionRecoveryCode extends RecoveryCode
{
    /** @var string|\UnitEnum|null Connection name this subclass routes all I/O through. */
    protected $connection = 'secondary';
}
