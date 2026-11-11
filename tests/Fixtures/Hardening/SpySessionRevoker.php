<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * Runs the revoker it wraps, if any, then notes the call, so the default seam's
 * writes stay apart from what happens after them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SpySessionRevoker implements SessionRevoker
{
    /**
     * @param  \Tests\Fixtures\Hardening\LockOrderRecorder  $recorder
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $wrapped
     * @param  ?\Closure(): void  $onFactorRemoved
     */
    public function __construct(

        /** The log the calls go to. */
        private LockOrderRecorder $recorder,

        /** Passed each call. */
        private ?SessionRevoker $wrapped = null,

        /** Runs first on a factor's removal. */
        private ?\Closure $onFactorRemoved = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $application, string $session): RemovalRevocation
    {
        if ($this->onFactorRemoved !== null) {
            ($this->onFactorRemoved)();
        }

        if ($this->wrapped === null) {
            $this->recorder->seam('factorRemoved');

            return RemovalRevocation::othersEnded();
        }

        $revocation = $this->wrapped->factorRemoved($identity, $factorId, $application, $session);

        $this->recorder->seam('factorRemoved');

        return $revocation;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        $this->wrapped?->revokeAll($identity);

        $this->recorder->seam('revokeAll');
    }
}
