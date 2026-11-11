<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Reads `isMfaActive()` from the identity contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityContractActiveState implements ActiveStateResolver
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return $identity->isMfaActive();
    }
}
