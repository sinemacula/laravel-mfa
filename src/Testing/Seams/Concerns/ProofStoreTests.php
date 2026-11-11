<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;

/**
 * The `ProofStore` contract kit; each check delegates to `ProofStoreContract`.
 * The defaults suit a store that keeps its own sign-ins and proofs and honours
 * the verification generation; a store over an authentication layer overrides
 * the protected hooks to act through that layer.
 *
 * The checks add a password first factor to whatever the sign-in holds; an
 * adapter that cannot record one records an equivalent proof, never skips it.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ProofStoreTests
{
    /**
     * @return void
     */
    public function testProofStoreRefusesAProofOfAnotherSignIn(): void
    {
        [$store, $identity, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication()];

        $session = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($store, $identity, $application, $session, $this->arrangingProofStoreProofs($store, $identity, $application));
    }

    /**
     * @return void
     */
    public function testProofStoreRefusesAProofOfAnotherIdentity(): void
    {
        [$store, $identity, $other, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->otherProofStoreIdentity(), $this->proofStoreApplication()];

        $otherSession = $this->proofStoreSignIn($other, $application);
        $session      = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertRefusesAProofOfAnotherIdentity(
            $store,
            $identity,
            $other,
            $application,
            $session,
            $otherSession,
            $this->arrangingProofStoreProofs($store, $identity, $application),
        );
    }

    /**
     * @return void
     */
    public function testProofStoreRefusesAProofOfAnotherApplication(): void
    {
        [$store, $identity, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication()];

        $session = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertRefusesAProofOfAnotherApplication($store, $identity, $application, $session, $this->arrangingProofStoreProofs($store, $identity, $application));
    }

    /**
     * @return void
     */
    public function testProofStoreReadsOnlyTheNamedSignIn(): void
    {
        [$store, $identity, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication()];

        $session = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertReadsOnlyTheNamedSignIn(
            $store,
            $identity,
            $application,
            $session,
            fn (): string => $this->replaceProofStoreSignIn($store, $identity, $application, $session),
            $this->arrangingProofStoreProofs($store, $identity, $application),
        );
    }

    /**
     * @return void
     */
    public function testProofStoreForgetsASignInsProofsWithIt(): void
    {
        [$store, $identity, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication()];

        $session = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertForgettingASignInForgetsItsProofs(
            $store,
            $identity,
            $application,
            $session,
            fn (Proof $proof) => $this->arrangeProofStoreProof($store, $identity, $application, $session, $proof),
            fn () => $this->endProofStoreSignIn($store, $identity, $application),
        );
    }

    /**
     * @return void
     */
    public function testProofStoreStopsCountingVoidedProofs(): void
    {
        [$store, $identity, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication()];

        $session = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertVoidedProofsStopCounting(
            $store,
            $identity,
            $application,
            $session,
            $this->voidProofStoreProofs(...),
            fn (Proof $proof) => $this->arrangeProofStoreProof($store, $identity, $application, $session, $proof),
        );
    }

    /**
     * @return void
     */
    public function testProofStoreStopsCountingAForgottenFactor(): void
    {
        [$store, $identity, $application] = [$this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication()];

        $session = $this->proofStoreSignIn($identity, $application);

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting(
            $store,
            $identity,
            $application,
            $session,
            $this->proofStoreFactor($identity),
            fn (Proof $proof) => $this->arrangeProofStoreProof($store, $identity, $application, $session, $proof),
        );
    }

    /**
     * Asked once per check; a store backed by real sessions signs in here and
     * returns the session's id.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     */
    protected function proofStoreSignIn(MultiFactorAuthenticatable $identity, string $application): string // NOSONAR: the parameters are for an override
    {
        return ProofStoreContract::SESSION;
    }

    /**
     * Void the identity's proofs as a reset does; by default, by advancing its
     * verification generation.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Throwable
     */
    protected function voidProofStoreProofs(MultiFactorAuthenticatable $identity): void
    {
        ProofStoreContract::voidByGeneration($identity);
    }

    /**
     * Records through the store by default; override to record the same proof
     * through the layer that keeps them.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    protected function arrangeProofStoreProof(
        ProofStore $store,
        MultiFactorAuthenticatable $identity,
        string $application, // NOSONAR: for an override
        string $session, // NOSONAR: for an override
        Proof $proof,
    ): void {
        $store->record($identity, $proof);
    }

    /**
     * Sign out; forgets through the store by default.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    protected function endProofStoreSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        $store->forget($identity, $application);
    }

    /**
     * Sign in again and return the new sign-in's id; begins through the store
     * by default.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return string
     */
    protected function replaceProofStoreSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session): string
    {
        $store->begin($identity, $application, 'replaced-' . $session);

        return 'replaced-' . $session;
    }

    /**
     * By default `ProofStoreContract::FACTOR`. A store that counts a proof only
     * while the identity holds its factor enrols one here and returns its id.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    protected function proofStoreFactor(MultiFactorAuthenticatable $identity): string // NOSONAR: the parameter is for an override
    {
        return ProofStoreContract::FACTOR;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    abstract protected function proofStore(): ProofStore;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function proofStoreIdentity(): MultiFactorAuthenticatable;

    /**
     * Of the same kind, with no sign-in until a check begins one.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function otherProofStoreIdentity(): MultiFactorAuthenticatable;

    /**
     * @return string
     */
    abstract protected function proofStoreApplication(): string;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \Closure(\SineMacula\Laravel\Mfa\Proofs\Proof): void
     */
    private function arrangingProofStoreProofs(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): \Closure
    {
        return fn (Proof $proof) => $this->arrangeProofStoreProof($store, $identity, $application, $proof->binding->sessionId, $proof);
    }
}
