<?php

declare(strict_types = 1);

namespace Tests\Fixtures\RecoveryCodes;

use SineMacula\Laravel\Mfa\Models\RecoveryCode;

/**
 * A recovery code model on the `secondary` connection, refused at boot unless
 * that is the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecondaryConnectionRecoveryCode extends RecoveryCode
{
    /** @var string|\UnitEnum|null */
    protected $connection = 'secondary';
}
