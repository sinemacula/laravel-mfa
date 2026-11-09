<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;

/**
 * The `ProofStore` contract kit: a proof of another sign-in, identity or
 * application is refused, the proofs read for a sign-in are the current
 * sign-in's only, a sign-in's proofs go with it, a proof made before the
 * identity's proofs are voided stops counting, and forgetting a factor stops
 * its proofs counting.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ProofStoreContract`. A store backed by an
 * authentication layer's sessions also overrides `proofStoreSignIn()`, to sign
 * the identity in for real, and `voidProofStoreProofs()`, to void its proofs
 * the way that layer does. A store whose proofs and sign-ins that layer alone
 * writes overrides `arrangeProofStoreProof()`, to record each proof the checks
 * need through the layer, `endProofStoreSignIn()`, to sign the identity out
 * through it, and `proofStoreFactor()`, to name a factor the identity holds.
 * The defaults suit a store that keeps its own sign-ins and proofs and honours
 * the verification generation. The checks arrange a password first factor on
 * top of whatever the sign-in already holds: an adapter that cannot record one
 * makes its override record an equivalent proof, never skip it.
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
     * A proof bound to another sign-in is refused, and not kept.
     *
     * @return void
     */
    public function testProofStoreRefusesAProofOfAnotherSignIn(): void
    {
        [$identity, $application] = [$this->proofStoreIdentity(), $this->proofStoreApplication()];

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($this->proofStore(), $identity, $application, $this->proofStoreSignIn($identity, $application));
    }

    /**
     * A proof bound to another identity is refused, and not kept.
     *
     * @return void
     */
    public function testProofStoreRefusesAProofOfAnotherIdentity(): void
    {
        [$identity, $application] = [$this->proofStoreIdentity(), $this->proofStoreApplication()];

        ProofStoreContract::assertRefusesAProofOfAnotherIdentity($this->proofStore(), $identity, $application, $this->proofStoreSignIn($identity, $application));
    }

    /**
     * A proof bound to another application is refused, and not kept.
     *
     * @return void
     */
    public function testProofStoreRefusesAProofOfAnotherApplication(): void
    {
        [$identity, $application] = [$this->proofStoreIdentity(), $this->proofStoreApplication()];

        ProofStoreContract::assertRefusesAProofOfAnotherApplication($this->proofStore(), $identity, $application, $this->proofStoreSignIn($identity, $application));
    }

    /**
     * The proofs read for a sign-in are the current sign-in's only.
     *
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
            fn (Proof $proof) => $this->arrangeProofStoreProof($store, $identity, $application, $session, $proof),
        );
    }

    /**
     * Forgetting a sign-in forgets its proofs.
     *
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
     * A proof made before the identity's proofs are voided stops counting.
     *
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
     * Forgetting a factor stops its proofs counting, and only its.
     *
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
     * The sign-in each check begins for the identity on the application, asked
     * once a check: a store backed by real sessions signs the identity in here
     * and returns the session's id.
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
     * Void every proof the identity has made, the way the store's proofs stop
     * counting on a reset: by default, by advancing its verification
     * generation.
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
     * Put the proof in the sign-in, as a check needs it counted: by default, by
     * recording it through the store. A store whose proofs another layer
     * records has that layer record the same proof.
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
     * End the identity's sign-in on the application, as signing out does: by
     * default, by forgetting it through the store. A store whose sign-ins
     * another layer ends signs the identity out through that layer.
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
     * The factor the further proof names, asked once for the factor check: by
     * default `ProofStoreContract::FACTOR`. A store that counts a proof only
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
     * The proof store under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    abstract protected function proofStore(): ProofStore;

    /**
     * An identity the store keeps proofs for.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function proofStoreIdentity(): MultiFactorAuthenticatable;

    /**
     * The application its sign-ins are on.
     *
     * @return string
     */
    abstract protected function proofStoreApplication(): string;
}
