<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;

/**
 * Offers no self-service recovery, so a person who has lost every factor and
 * their recovery codes is reset by someone else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NoSelfServiceRecovery implements SelfServiceRecovery
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return bool
     */
    #[\Override]
    public function isOffered(MultiFactorAuthenticatable $identity, string $application): bool
    {
        return false;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function start(MultiFactorAuthenticatable $identity, string $application): void
    {
        throw new OperationRefusedException(FailureReason::SELF_SERVICE_RECOVERY_UNAVAILABLE, 'The application offers no self-service recovery.');
    }
}
