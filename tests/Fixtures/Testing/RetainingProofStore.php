<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A store whose sign-ins are arranged elsewhere, as an authentication layer's
 * are: `begin()` does nothing, so a session it was told of and the proofs it
 * holds stay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RetainingProofStore implements ProofStore
{
    /** @var list<\SineMacula\Laravel\Mfa\Proofs\Proof> The proofs held. */
    private array $proofs = [];

    /**
     * Constructor.
     *
     * @param  ?string  $session
     */
    public function __construct(

        /** The sign-in the store knows of, if any. */
        private readonly ?string $session = null,
    ) {}

    /**
     * Do nothing: the sign-in is arranged elsewhere.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        // The sign-in is arranged elsewhere.
    }

    /**
     * The sign-in the store knows of.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        return $this->session;
    }

    /**
     * Keep the proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $this->proofs[] = $proof;
    }

    /**
     * Every proof held, when the sign-in named is the one the store knows of.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        return $sessionId === $this->session ? $this->proofs : [];
    }

    /**
     * Forget nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        // Nothing here needs it.
    }

    /**
     * Forget nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        // Nothing here needs it.
    }
}
