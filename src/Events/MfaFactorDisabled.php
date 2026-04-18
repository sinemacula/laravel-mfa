<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Dispatched when an existing MFA factor is disabled or removed from an
 * identity.
 *
 * Fires after the factor record has been deleted or otherwise marked inactive.
 * Consumers can subscribe to emit audit-log entries, send confirmation
 * notifications, or recalculate whether the identity still has enough active
 * factors to satisfy policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class MfaFactorDisabled
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     */
    public function __construct(

        /** Identity the factor was removed from. */
        public Authenticatable $identity,

        /** Factor that was disabled / removed. */
        public Factor $factor,

        /** Driver name the disabled factor was registered with. */
        public string $driver,

    ) {}
}
