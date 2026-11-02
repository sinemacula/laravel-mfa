<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use Tests\Fixtures\Seams\Enums\ProofStoreFlaw;

/**
 * An in-memory proof store that keeps the contract but for one flaw: it refuses
 * a proof before a sign-in is begun and one of another sign-in, keeps the
 * current sign-in's proofs, forgets a factor's proofs, and forgets the sign-in
 * with its proofs, except where its flaw says otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FlawedProofStore implements ProofStore
{
    /** @var list<\SineMacula\Laravel\Mfa\Proofs\Proof> The proofs kept. */
    private array $proofs = [];

    /** @var ?string The sign-in begun last. */
    private ?string $session = null;

    /**
     * Constructor.
     *
     * @param  \Tests\Fixtures\Seams\Enums\ProofStoreFlaw  $flaw
     */
    public function __construct(

        /** The store's one flaw. */
        private readonly ProofStoreFlaw $flaw,
    ) {}

    /**
     * Begin the sign-in, with no proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $this->session = $sessionId;
        $this->proofs  = [];
    }

    /**
     * The sign-in begun last.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        if ($this->session !== null && $this->flaw === ProofStoreFlaw::WRONG_SESSION) {
            return 'another-sign-in';
        }

        return $this->session;
    }

    /**
     * Keep a proof of the current sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    #[\Override]
    public function record(Proof $proof): void
    {
        if ($this->session === null) {
            throw new ProofRefusedException('No sign-in is begun.');
        }

        if ($proof->binding->sessionId !== $this->session && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_SIGN_IN) {
            throw new ProofRefusedException('The proof is bound to another sign-in.');
        }

        if ($this->flaw === ProofStoreFlaw::DROPS_PROOFS) {
            return;
        }

        $this->proofs[] = $proof;
    }

    /**
     * Every proof kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        return $this->proofs;
    }

    /**
     * Forget the proofs made with the factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $this->proofs = array_values(array_filter($this->proofs, static fn (Proof $proof): bool => $proof->reference !== $factorId));
    }

    /**
     * Forget the sign-in and its proofs.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        if ($this->flaw !== ProofStoreFlaw::KEEPS_SESSION) {
            $this->session = null;
        }

        if ($this->flaw === ProofStoreFlaw::KEEPS_PROOFS) {
            return;
        }

        $this->proofs = [];
    }
}
