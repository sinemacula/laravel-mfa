<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * A faulty revoker: it forgets the other session's sign-in at once, outside the
 * caller's transaction, so a revocation that rolls back still ends it; or,
 * given a failure, throws it instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ForgettingSessionRevoker implements SessionRevoker
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $otherSession
     * @param  string  $application
     * @param  ?\LogicException  $failure
     */
    public function __construct(

        /** The store of the other session. */
        private ProofStore $otherSession,

        /** The application the other session is signed in on. */
        private string $application,

        /** The failure to throw instead of revoking, if any. */
        private ?\LogicException $failure = null,
    ) {}

    /**
     * Forget the other session's sign-in at once, or throw the failure.
     *
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
     * Forget the other session's sign-in at once, or throw the failure.
     *
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
