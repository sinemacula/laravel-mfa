<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Answers the opposite of the identity's own state, so a test can tell the
 * bound resolver's answer from the model's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvertedActiveState implements ActiveStateResolver
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return !$identity->isMfaActive();
    }
}
