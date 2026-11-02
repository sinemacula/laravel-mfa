<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Active tenant resolver contract.
 *
 * The tenant whose authentication policy applies to the identity's session on
 * the application, read from validated session context, as an opaque id. It is
 * authoritative: what it names is what requirements are composed with, when a
 * session is evaluated and when a factor change evaluates it again, so an
 * adapter binds it to the session's own validated tenant, never to what a
 * request merely claims and never to an event's descriptive context. No tenant
 * means no tenant requirement applies.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ActiveTenantResolver
{
    /**
     * The identity's active tenant on the application, or `null` when it has
     * none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string;
}
