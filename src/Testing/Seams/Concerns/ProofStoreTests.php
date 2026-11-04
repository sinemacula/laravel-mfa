<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;

/**
 * The `ProofStore` contract kit: a proof of another sign-in is refused, a
 * sign-in's proofs go with it, a proof made before the identity's proofs are
 * voided stops counting, and forgetting a factor stops its proofs counting.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ProofStoreContract`. A store backed by an
 * authentication layer's sessions also overrides `proofStoreSignIn()`, to sign
 * the identity in for real, and `voidProofStoreProofs()`, to void its proofs
 * the way that layer does; the defaults suit a store that keeps its own
 * sign-ins and honours the verification generation.
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
     * Forgetting a sign-in forgets its proofs.
     *
     * @return void
     */
    public function testProofStoreForgetsASignInsProofsWithIt(): void
    {
        [$identity, $application] = [$this->proofStoreIdentity(), $this->proofStoreApplication()];

        ProofStoreContract::assertForgettingASignInForgetsItsProofs($this->proofStore(), $identity, $application, $this->proofStoreSignIn($identity, $application));
    }

    /**
     * A proof made before the identity's proofs are voided stops counting.
     *
     * @return void
     */
    public function testProofStoreStopsCountingVoidedProofs(): void
    {
        [$identity, $application] = [$this->proofStoreIdentity(), $this->proofStoreApplication()];

        ProofStoreContract::assertVoidedProofsStopCounting(
            $this->proofStore(),
            $identity,
            $application,
            $this->proofStoreSignIn($identity, $application),
            $this->voidProofStoreProofs(...),
        );
    }

    /**
     * Forgetting a factor stops its proofs counting, and only its.
     *
     * @return void
     */
    public function testProofStoreStopsCountingAForgottenFactor(): void
    {
        [$identity, $application] = [$this->proofStoreIdentity(), $this->proofStoreApplication()];

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($this->proofStore(), $identity, $application, $this->proofStoreSignIn($identity, $application));
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
