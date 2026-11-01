<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * First factor resolver contract.
 *
 * Reads the proof of the first factor that started the identity's current
 * session: its method, its channel (kind and destination or credential), the
 * properties it observed and its time. It answers only from a trusted source
 * (the session's record, or the application's declaration); `null` means the
 * first factor is unknown, so no combination is accepted and no level is
 * established.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FirstFactorResolver
{
    /**
     * The first factor's proof on the identity's current session, or `null`
     * when it is unknown or untrusted.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function resolve(MultiFactorAuthenticatable $identity, string $application): ?Proof;
}
