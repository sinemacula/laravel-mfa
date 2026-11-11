<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * The tenant whose policy applies to the session, as an opaque id; bind it to
 * the session's validated tenant, never to what a request or event claims.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ActiveTenantResolver
{
    /**
     * The active tenant, or `null` when no tenant requirement applies.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string;
}
