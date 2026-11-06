<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An active state resolver that answers the opposite of what the identity says
 * of itself, so a test can tell the bound resolver's answer from the model's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvertedActiveState implements ActiveStateResolver
{
    /**
     * Whether the identity is active: only when it says it is not.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return !$identity->isMfaActive();
    }
}
