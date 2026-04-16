<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;

/**
 * Dispatched whenever the MFA manager rejects a verification attempt.
 *
 * Carries a machine-readable failure reason so downstream consumers
 * (audit-log sinks, SIEM pipelines, support tooling) can attribute
 * failures without parsing human-readable messages. Fires for every
 * non-success branch of the manager's verification pipeline — invalid
 * codes, expired challenges, locked factors, unresolvable drivers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class MfaVerificationFailed
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason  $reason
     */
    public function __construct(

        /** Identity whose verification attempt failed. */
        public Authenticatable $identity,

        /** Factor the attempt was made against, or null when unresolved. */
        public ?Factor $factor,

        /** Driver name that handled (or would have handled) verification. */
        public string $driver,

        /** Machine-readable reason for the failure. */
        public MfaVerificationFailureReason $reason,

    ) {}
}
