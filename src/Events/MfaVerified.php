<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Dispatched after the MFA manager records a successful verification
 * against a factor.
 *
 * Fires after the factor's attempt counters have been reset, the
 * verification timestamp has been stamped, and the bound verification
 * store has been updated for the current identity. Consumers can
 * subscribe to extend the request-scoped verification window, emit
 * audit-log entries, or refresh cached authorisation decisions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class MfaVerified
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     */
    public function __construct(

        /** Identity whose verification succeeded. */
        public Authenticatable $identity,

        /** Factor used to complete the verification. */
        public Factor $factor,

        /** Driver name that handled the verification. */
        public string $driver,

    ) {}
}
