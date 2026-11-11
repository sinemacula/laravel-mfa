<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Reads the proof of the first factor that started the identity's session, from
 * a trusted source only.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FirstFactorResolver
{
    /**
     * The first factor's proof, or `null` when it is unknown or untrusted, so
     * no combination is accepted.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function resolve(MultiFactorAuthenticatable $identity, string $application): ?Proof;
}
