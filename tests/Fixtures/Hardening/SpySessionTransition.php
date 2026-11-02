<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A session transition that notes each call and does nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SpySessionTransition implements SessionTransition
{
    /**
     * Constructor.
     *
     * @param  \Tests\Fixtures\Hardening\LockOrderRecorder  $recorder
     */
    public function __construct(

        /** The log the calls go to. */
        private LockOrderRecorder $recorder,
    ) {}

    /**
     * Note the call.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @return void
     */
    #[\Override]
    public function returnToPending(MultiFactorAuthenticatable $identity, string $application, Requirement $outstanding): void
    {
        $this->recorder->seam('returnToPending');
    }
}
