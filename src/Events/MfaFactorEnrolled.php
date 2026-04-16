<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Dispatched when a new MFA factor is enrolled against an identity.
 *
 * Fires after the factor record has been persisted and any per-driver
 * setup (TOTP secret generation, backup code minting) has completed.
 * Consumers can subscribe to emit audit-log entries, send confirmation
 * notifications, or trigger downstream access-policy recalculation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class MfaFactorEnrolled
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     */
    public function __construct(

        /** Identity the factor was enrolled against. */
        public Authenticatable $identity,

        /** Newly enrolled factor. */
        public Factor $factor,

        /** Driver name the factor is registered with. */
        public string $driver,

    ) {}
}
