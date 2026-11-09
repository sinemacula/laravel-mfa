<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Seams\Enums\ProofStoreFlaw;

/**
 * An in-memory proof store that keeps the contract but for one flaw: it refuses
 * a proof before a sign-in is begun and one of another sign-in, identity or
 * application, keeps the current sign-in's proofs and reads them for that
 * sign-in only, forgets a factor's proofs, and forgets the sign-in with its
 * proofs, except where its flaw says otherwise.
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

    /** @var ?string The application the sign-in was begun on. */
    private ?string $application = null;

    /** @var ?string The sign-in begun last, kept when it is forgotten. */
    private ?string $begun = null;

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
        $this->session     = $sessionId;
        $this->begun       = $sessionId;
        $this->application = $application;
        $this->proofs      = [];
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
     * Keep the identity's proof of the current sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        if ($this->session === null) {
            throw new ProofRefusedException('No sign-in is begun.');
        }

        if ($proof->binding->sessionId !== $this->session && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_SIGN_IN) {

            if ($this->flaw === ProofStoreFlaw::KEEPS_A_REFUSED_PROOF) {
                $this->proofs[] = $proof;
            }

            throw new ProofRefusedException('The proof is bound to another sign-in.');
        }

        if (!ProofOwner::of($identity)->owns($proof->binding) && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_IDENTITY) {
            throw new ProofRefusedException('The proof is bound to another identity.');
        }

        if ($proof->binding->application !== $this->application && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_APPLICATION) {
            throw new ProofRefusedException('The proof is bound to another application.');
        }

        if ($this->flaw === ProofStoreFlaw::DROPS_PROOFS) {
            return;
        }

        $this->proofs[] = $proof;
    }

    /**
     * Every proof kept, when the sign-in named is the current one, or, for a
     * store that keeps the proofs, the one begun last though it was forgotten.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        $readable = $sessionId === $this->session
            || $this->flaw     === ProofStoreFlaw::READS_ANY_SIGN_IN
            || ($this->flaw === ProofStoreFlaw::KEEPS_PROOFS && $sessionId === $this->begun);

        return $readable ? $this->proofs : [];
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
