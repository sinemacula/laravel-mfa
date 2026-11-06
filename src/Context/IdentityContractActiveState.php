<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The default `ActiveStateResolver`, which reads the identity contract: an
 * identity is active when its `isMfaActive()` says so.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityContractActiveState implements ActiveStateResolver
{
    /**
     * Whether the identity is active.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return $identity->isMfaActive();
    }
}
