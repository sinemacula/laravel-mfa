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
use Tests\Fixtures\Seams\LayerWrittenProofStore;
use Tests\Fixtures\Seams\SignInRowsProofStore;
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

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that keeps counting an earlier generation.
     *
     * @return void
     */
    public function testRejectsAStoreThatIgnoresTheGeneration(): void
    {
        $this->expectException(AssertionFailedError::class);

        $void = ProofStoreContract::voidByGeneration(...);

        ProofStoreContract::assertVoidedProofsStopCounting(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION, $void);
    }

    /**
     * The kit rejects a store that forgets nothing.
     *
     * @return void
     */
    public function testRejectsAStoreThatForgetsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingASignInForgetsItsProofs(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
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

        $store = new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_SIGN_IN);

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that keeps a proof it refuses.
     *
     * @return void
     */
    public function testRejectsAStoreThatKeepsAProofItRefuses(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A refused proof must change nothing.');

        $store = new FlawedProofStore(ProofStoreFlaw::KEEPS_A_REFUSED_PROOF);

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that keeps a proof of another identity on the
     * identity's current sign-in.
     *
     * @return void
     */
    public function testRejectsAStoreThatKeepsAProofOfAnotherIdentity(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof bound to another identity must be refused by throwing a ProofRefusedException.');

        $store = new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_IDENTITY);

        ProofStoreContract::assertRefusesAProofOfAnotherIdentity($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that keeps a proof of another application under
     * the current sign-in's id.
     *
     * @return void
     */
    public function testRejectsAStoreThatKeepsAProofOfAnotherApplication(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof bound to another application must be refused by throwing a ProofRefusedException.');

        $store = new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_APPLICATION);

        ProofStoreContract::assertRefusesAProofOfAnotherApplication($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that reads the current sign-in's proofs for
     * whichever sign-in is named.
     *
     * @return void
     */
    public function testRejectsAStoreThatReadsAnySignIn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A sign-in that is not the current one must yield no proof.');

        $store = new FlawedProofStore(ProofStoreFlaw::READS_ANY_SIGN_IN);

        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that reads no proof for the sign-in named.
     *
     * @return void
     */
    public function testRejectsAStoreThatReadsNothingForTheNamedSignIn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of the current sign-in must be read for it.');

        $store = new FlawedProofStore(ProofStoreFlaw::DROPS_PROOFS);

        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * Each refusal and the named read pass on a store that keeps them, and fail
     * on none of its other flaws.
     *
     * @return void
     */
    public function testTheNewChecksPassAStoreThatKeepsThem(): void
    {
        $identity = $this->proofStoreIdentity();

        foreach ([ProofStoreFlaw::WRONG_SESSION, ProofStoreFlaw::KEEPS_SESSION, ProofStoreFlaw::KEEPS_PROOFS] as $flaw) {
            ProofStoreContract::assertRefusesAProofOfAnotherIdentity(new FlawedProofStore($flaw), $identity, 'web', ProofStoreContract::SESSION);
            ProofStoreContract::assertRefusesAProofOfAnotherApplication(new FlawedProofStore($flaw), $identity, 'web', ProofStoreContract::SESSION);
        }

        ProofStoreContract::assertReadsOnlyTheNamedSignIn(new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_IDENTITY), $identity, 'web', ProofStoreContract::SESSION);

        $this->addToAssertionCount(1);
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

        ProofStoreContract::assertForgettingASignInForgetsItsProofs(new FlawedProofStore($flaw), $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * The kit rejects a store that keeps the proofs of a forgotten factor.
     *
     * @return void
     */
    public function testRejectsAStoreThatForgetsNoFactor(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * Each check runs on what the closures it is given write and end, not on
     * the store's own `record()` and `forget()`.
     *
     * @return void
     */
    public function testTheChecksUseTheClosuresTheyAreGiven(): void
    {
        $identity = $this->proofStoreIdentity();
        $store    = new LayerWrittenProofStore;

        ProofStoreContract::assertForgettingASignInForgetsItsProofs($store, $identity, 'web', $store->signIn(), $store->write(...), $store->signOut(...));
        ProofStoreContract::assertVoidedProofsStopCounting($store, $identity, 'web', $store->signIn(), $store->signOut(...), $store->write(...));
        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($store, $identity, 'web', $store->signIn(), $store->enrol(), $store->write(...));
        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $identity, 'web', $store->signIn(), $store->write(...));

        $this->addToAssertionCount(1);
    }

    /**
     * A void is not checked on an arranged proof that never counted, even when
     * the sign-in already held a proof of its own.
     *
     * @return void
     */
    public function testRejectsAVoidWhoseArrangedProofNeverCounted(): void
    {
        $identity = $this->proofStoreIdentity();
        $store    = new SignInRowsProofStore;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of the current sign-in must count before the proofs are voided.');

        ProofStoreContract::assertVoidedProofsStopCounting($store, $identity, 'web', $store->arrange($identity, 'web'), $store->void(...), static function (): void {});
    }

    /**
     * A factor is not forgotten on arranged proofs that never counted.
     *
     * @return void
     */
    public function testRejectsAFactorCheckWhoseArrangedProofsNeverCounted(): void
    {
        $identity = $this->proofStoreIdentity();
        $store    = new LayerWrittenProofStore;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Both proofs must count before the factor is forgotten.');

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($store, $identity, 'web', $store->signIn());
    }

    /**
     * The factor check counts against the proofs the sign-in held when begun.
     *
     * @return void
     */
    public function testTheFactorCheckCountsAgainstWhatTheSignInHeld(): void
    {
        $identity = $this->proofStoreIdentity();
        $store    = new SignInRowsProofStore;

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($store, $identity, 'web', $store->arrange($identity, 'web'));

        $this->addToAssertionCount(1);
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
