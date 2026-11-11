<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A faulty proof store that keeps every proof it is given and forgets nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeepingProofStore implements ProofStore
{
    /** @var list<\SineMacula\Laravel\Mfa\Proofs\Proof> */
    private array $proofs = [];

    /** @var ?string The sign-in begun last. */
    private ?string $session = null;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $this->session = $sessionId;
    }

    /**
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        return $this->proofs;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        // A faulty store forgets nothing.
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        // A faulty store forgets nothing.
    }
}
