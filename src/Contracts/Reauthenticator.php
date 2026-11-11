<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Proves the first factor again on an active session, for a first additional
 * factor and for operations that require it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Reauthenticator
{
    /**
     * The fresh first-factor proof, or `null` to refuse the change that asked.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function reauthenticate(MultiFactorAuthenticatable $identity, string $application): ?Proof;
}
