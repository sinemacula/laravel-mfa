<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;

/**
 * The `ProofStore` contract kit: a proof of another sign-in is refused, a
 * sign-in's proofs go with it, an earlier verification generation stops
 * counting, and forgetting a factor stops its proofs counting.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ProofStoreContract`.
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
        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication());
    }

    /**
     * Forgetting a sign-in forgets its proofs.
     *
     * @return void
     */
    public function testProofStoreForgetsASignInsProofsWithIt(): void
    {
        ProofStoreContract::assertForgettingASignInForgetsItsProofs($this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication());
    }

    /**
     * A proof made under an earlier verification generation stops counting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofStoreStopsCountingAnEarlierGeneration(): void
    {
        ProofStoreContract::assertAnEarlierGenerationStopsCounting($this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication());
    }

    /**
     * Forgetting a factor stops its proofs counting, and only its.
     *
     * @return void
     */
    public function testProofStoreStopsCountingAForgottenFactor(): void
    {
        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($this->proofStore(), $this->proofStoreIdentity(), $this->proofStoreApplication());
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
