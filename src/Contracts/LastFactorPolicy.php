<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Last factor policy contract.
 *
 * Whether the identity's last confirmed factor, or the last one an application
 * or requirement accepts, may be removed by the identity acting on the
 * application. It is asked before the removal and again when it commits, so
 * required MFA cannot be turned off by the person it applies to.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LastFactorPolicy
{
    /**
     * Whether the factor, the last of its kind for the identity, may be
     * removed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return bool
     */
    public function allowsRemoval(MultiFactorAuthenticatable $identity, string $application, Factor $factor): bool;
}
