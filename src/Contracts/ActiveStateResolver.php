<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Active state resolver contract.
 *
 * Whether an identity is active. An inactive identity, one suspended or
 * deactivated by the layer that knows, is refused every operation, offered no
 * factor and meets no requirement. Without an authentication layer that knows
 * the identity's state, it is what the identity's own `isMfaActive()` says.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ActiveStateResolver
{
    /**
     * Whether the identity is active.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    public function isActive(MultiFactorAuthenticatable $identity): bool;
}
