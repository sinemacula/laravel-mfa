<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * Forgets the other session's sign-in at once, outside the caller's
 * transaction, so a revocation that rolls back still ends it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ForgettingSessionRevoker implements SessionRevoker
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $otherSession
     * @param  string  $application
     * @param  ?\LogicException  $failure
     */
    public function __construct(

        /** The other session's store. */
        private ProofStore $otherSession,

        /** The other session's application. */
        private string $application,

        /** Thrown instead of revoking. */
        private ?\LogicException $failure = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \LogicException
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $application, string $session): RemovalRevocation
    {
        $this->revokeAll($identity);

        return RemovalRevocation::othersEnded();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        $this->otherSession->forget($identity, $this->application);
    }
}
