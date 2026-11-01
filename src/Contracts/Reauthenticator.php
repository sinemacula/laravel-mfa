<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Reauthenticator contract.
 *
 * Proves the first factor again on an active session, for an identity enrolling
 * its first additional factor and for operations that require it, and returns
 * the proof: its method, channel, observed properties, time and session. It
 * fails closed: `null` means the first factor was not proved again, and the
 * change that asked is refused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Reauthenticator
{
    /**
     * The proof of the first factor made again on the identity's current
     * session, or `null` when none was made.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function reauthenticate(MultiFactorAuthenticatable $identity, string $application): ?Proof;
}
