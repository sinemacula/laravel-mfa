<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ProofStoreTests;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\Enums\ProofStoreFlaw;
use Tests\Fixtures\Seams\FlawedProofStore;
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
     * The kit rejects a store that refuses a proof of another sign-in only
     * while no sign-in is begun.
     *
     * @return void
     */
    public function testRejectsAStoreThatAcceptsAProofOfAnotherSignInOnceOneIsBegun(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn(new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_SIGN_IN), $this->proofStoreIdentity(), 'web');
    }

    /**
     * Rows of a store that breaks one part of forgetting a sign-in.
     *
     * @return iterable<string, array{\Tests\Fixtures\Seams\Enums\ProofStoreFlaw}>
     */
    public static function signInFlaws(): iterable
    {
        yield 'another sign-in is current' => [ProofStoreFlaw::WRONG_SESSION];
        yield 'no proof is kept' => [ProofStoreFlaw::DROPS_PROOFS];
        yield 'the sign-in stays current' => [ProofStoreFlaw::KEEPS_SESSION];
        yield 'the proofs are kept' => [ProofStoreFlaw::KEEPS_PROOFS];
    }

    /**
     * The kit rejects a store that breaks any one part of keeping and
     * forgetting a sign-in.
     *
     * @param  \Tests\Fixtures\Seams\Enums\ProofStoreFlaw  $flaw
     * @return void
     */
    #[DataProvider('signInFlaws')]
    public function testRejectsAStoreThatForgetsASignInWrongly(ProofStoreFlaw $flaw): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingASignInForgetsItsProofs(new FlawedProofStore($flaw), $this->proofStoreIdentity(), 'web');
    }

    /**
     * The kit rejects a store that keeps the proofs of a forgotten factor.
     *
     * @return void
     */
    public function testRejectsAStoreThatForgetsNoFactor(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting(new KeepingProofStore, $this->proofStoreIdentity(), 'web');
    }

    /**
     * The session store, over a session of its own.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    #[\Override]
    protected function proofStore(): ProofStore
    {
        return new SessionProofStore(new Store('contract', new ArraySessionHandler(10)));
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
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
    #[\Override]
    protected function proofStoreApplication(): string
    {
        return 'web';
    }
}
