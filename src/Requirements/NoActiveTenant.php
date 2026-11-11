<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The default `ActiveTenantResolver`: without an adapter no validated session
 * context names a tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NoActiveTenant implements ActiveTenantResolver
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        return null;
    }
}
