<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Dispatched after the MFA manager successfully issues a challenge against
 * a factor.
 *
 * For delivery-based drivers (email, SMS) this fires after the transport
 * handoff completes; for client-generated drivers (TOTP) this fires to
 * signal that a verification window is now active even though no server
 * transport ran. Consumers can subscribe to audit challenge issuance,
 * trigger rate-limiting side effects, or write UI hints.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class MfaChallengeIssued
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     */
    public function __construct(

        /** Identity the challenge was issued on behalf of. */
        public Authenticatable $identity,

        /** Factor against which the challenge was issued. */
        public Factor $factor,

        /** Driver name that handled the challenge issuance. */
        public string $driver,

    ) {}
}
