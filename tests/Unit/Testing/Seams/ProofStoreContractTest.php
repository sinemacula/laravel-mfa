<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreTests;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\KeepingProofStore;
use Tests\TestCase;

/**
 * The `ProofStore` contract kit proves the session store, and rejects a store
 * that keeps every proof it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreContract::class)]
#[CoversClass(SessionProofStore::class)]
final class ProofStoreContractTest extends TestCase
{
    use ProofStoreTests;

    /**
     * The kit rejects a store that keeps a proof of another sign-in.
     *
     * @return void
     */
    public function testRejectsAStoreThatKeepsAProofOfAnotherSignIn(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn(new KeepingProofStore, $this->proofStoreIdentity(), 'web');
    }

    /**
     * The kit rejects a store that keeps counting an earlier generation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAStoreThatIgnoresTheGeneration(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertAnEarlierGenerationStopsCounting(new KeepingProofStore, $this->proofStoreIdentity(), 'web');
    }

    /**
     * The kit rejects a store that forgets nothing.
     *
     * @return void
     */
    public function testRejectsAStoreThatForgetsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingASignInForgetsItsProofs(new KeepingProofStore, $this->proofStoreIdentity(), 'web');
    }

    /**
     * The session store, over a session of its own.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    protected function proofStore(): ProofStore
    {
        return new SessionProofStore(new Store('contract', new ArraySessionHandler(10)));
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function proofStoreIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'store@example.test']);
    }

    /**
     * The application.
     *
     * @return string
     */
    protected function proofStoreApplication(): string
    {
        return 'web';
    }
}
