<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ProofStoreTests;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\Enums\ProofStoreFlaw;
use Tests\Fixtures\Seams\FlawedProofStore;
use Tests\Fixtures\Seams\InterceptedProofStore;
use Tests\Fixtures\Seams\KeepingProofStore;
use Tests\Fixtures\Seams\LayerWrittenProofStore;
use Tests\Fixtures\Seams\SignInRowsProofStore;
use Tests\TestCase;

/**
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
     * @return void
     */
    public function testRejectsAStoreThatKeepsAProofOfAnotherSignIn(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * @return void
     */
    public function testRejectsAStoreThatIgnoresTheGeneration(): void
    {
        $this->expectException(AssertionFailedError::class);

        $void = ProofStoreContract::voidByGeneration(...);

        ProofStoreContract::assertVoidedProofsStopCounting(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION, $void);
    }

    /**
     * @return void
     */
    public function testRejectsAStoreThatForgetsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingASignInForgetsItsProofs(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * One that refuses such a proof only while no sign-in is begun.
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
     * On the identity's current sign-in.
     *
     * @return void
     */
    public function testRejectsAStoreThatKeepsAProofOfAnotherIdentity(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of another identity must be refused by throwing a ProofRefusedException.');

        $store = new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_IDENTITY);

        $this->assertRefusesAProofOfAnotherIdentity($store);
    }

    /**
     * Rather than the one it is recorded for; a proof naming an identity with
     * no sign-in would not show this.
     *
     * @return void
     */
    public function testRejectsAStoreThatJudgesTheIdentityTheBindingNames(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of another identity must be refused by throwing a ProofRefusedException.');

        $this->assertRefusesAProofOfAnotherIdentity(new FlawedProofStore(ProofStoreFlaw::KEYS_BY_BINDING), 'other-sign-in');
    }

    /**
     * Forgetting the current sign-in before throwing, on each kind of refusal.
     *
     * @return void
     */
    public function testRejectsAStoreThatDestroysTheSignInOnARefusal(): void
    {
        $identity = $this->proofStoreIdentity();
        $session  = ProofStoreContract::SESSION;
        $checks   = [
            'another sign-in'     => static fn (ProofStore $store) => ProofStoreContract::assertRefusesAProofOfAnotherSignIn($store, $identity, 'web', $session),
            'another identity'    => fn (ProofStore $store) => $this->assertRefusesAProofOfAnotherIdentity($store),
            'another application' => static fn (ProofStore $store) => ProofStoreContract::assertRefusesAProofOfAnotherApplication($store, $identity, 'web', $session),
        ];

        foreach ($checks as $refusal => $check) {
            try {
                $check(new FlawedProofStore(ProofStoreFlaw::DESTROYS_ON_REFUSAL));
            } catch (AssertionFailedError $failure) {
                self::assertSame('A refused proof must leave the sign-in current.', explode("\n", $failure->getMessage())[0], $refusal);

                continue;
            }

            self::fail(sprintf('The refusal of a proof of %s must catch a store that destroys the sign-in.', $refusal));
        }
    }

    /**
     * @return void
     */
    public function testRejectsAStoreThatKeepsARefusedProofForTheIdentityItNames(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A refused proof must not be kept for the identity it names.');

        $this->assertRefusesAProofOfAnotherIdentity(new FlawedProofStore(ProofStoreFlaw::KEEPS_FOR_THE_NAMED_IDENTITY));
    }

    /**
     * @return void
     */
    public function testRejectsAStoreThatEndsTheNamedIdentitysSignInOnARefusal(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A refused proof must leave the other identity\'s sign-in as it was.');

        $this->assertRefusesAProofOfAnotherIdentity(new FlawedProofStore(ProofStoreFlaw::ENDS_THE_NAMED_SIGN_IN));
    }

    /**
     * Such a sign-in could not show a refusal that changed it.
     *
     * @return void
     */
    public function testRejectsARefusalOnASignInHoldingNoProof(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of the current sign-in must be kept before the refusal.');

        $store = new LayerWrittenProofStore;

        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($store, $this->proofStoreIdentity(), 'web', $store->signIn(), static function (): void {});
    }

    /**
     * @return void
     */
    public function testRejectsAReplacementThatBeginsNoOtherSignIn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Replacing the sign-in must begin another.');

        $store   = new LayerWrittenProofStore;
        $session = $store->signIn();

        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $this->proofStoreIdentity(), 'web', $session, static fn (): string => $session, $store->write(...));
    }

    /**
     * @return void
     */
    public function testRejectsAReplacementThatIsNotCurrent(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The sign-in that replaced it must be the current one.');

        $store = new LayerWrittenProofStore;

        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $this->proofStoreIdentity(), 'web', $store->signIn(), $store->signIn(...), $store->write(...));
    }

    /**
     * @return void
     */
    public function testRejectsAStoreThatReadsNothingForTheReplacement(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of the sign-in that replaced it must be read for it.');

        $identity = $this->proofStoreIdentity();
        $store    = new LayerWrittenProofStore;
        $session  = $store->signIn();

        ProofStoreContract::assertReadsOnlyTheNamedSignIn(
            $store,
            $identity,
            'web',
            $session,
            static function () use ($store, $identity): string {
                $replacement = $store->signIn();

                $store->begin($identity, 'web', $replacement);

                return $replacement;
            },
            static function (Proof $proof) use ($store, $session): void {
                if ($proof->binding->sessionId !== $session) {
                    return;
                }

                $store->write($proof);
            },
        );
    }

    /**
     * @return void
     */
    public function testRejectsAStoreThatReadsAReplacedSignIn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A sign-in since replaced must yield no proof, though it held one.');

        $store = new FlawedProofStore(ProofStoreFlaw::RETAINS_SIGN_INS);

        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * Under the current sign-in's id.
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
     * Reading the current sign-in's proofs for whichever sign-in is named.
     *
     * @return void
     */
    public function testRejectsAStoreThatReadsAnySignIn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A session never begun must yield no proof.');

        $store = new FlawedProofStore(ProofStoreFlaw::READS_ANY_SIGN_IN);

        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
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
     * Each refusal check and the named read pass a store that keeps them, and
     * fail on none of its other flaws.
     *
     * @return void
     */
    public function testTheRefusalChecksPassAStoreThatKeepsThem(): void
    {
        $identity = $this->proofStoreIdentity();

        foreach ([ProofStoreFlaw::KEEPS_SESSION, ProofStoreFlaw::KEEPS_PROOFS, ProofStoreFlaw::RETAINS_SIGN_INS] as $flaw) {
            ProofStoreContract::assertRefusesAProofOfAnotherSignIn(new FlawedProofStore($flaw), $identity, 'web', ProofStoreContract::SESSION);
            $this->assertRefusesAProofOfAnotherIdentity(new FlawedProofStore($flaw));
            ProofStoreContract::assertRefusesAProofOfAnotherApplication(new FlawedProofStore($flaw), $identity, 'web', ProofStoreContract::SESSION);
        }

        foreach ([ProofStoreFlaw::ACCEPTS_ANY_IDENTITY, ProofStoreFlaw::KEYS_BY_BINDING, ProofStoreFlaw::DESTROYS_ON_REFUSAL] as $flaw) {
            ProofStoreContract::assertReadsOnlyTheNamedSignIn(new FlawedProofStore($flaw), $identity, 'web', ProofStoreContract::SESSION);
        }

        $this->addToAssertionCount(1);
    }

    /**
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
     * @return void
     */
    public function testRejectsAStoreThatForgetsNoFactor(): void
    {
        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting(new KeepingProofStore, $this->proofStoreIdentity(), 'web', ProofStoreContract::SESSION);
    }

    /**
     * As the package does, the factor is deleted before the store forgets it.
     *
     * @return void
     */
    public function testTheFactorIsDeletedBeforeTheStoreForgetsIt(): void
    {
        $identity = $this->proofStoreIdentity();
        $owner    = ProofOwner::of($identity);
        $factor   = Factor::query()->create(['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key, 'type' => 'totp', 'status' => 'confirmed']);
        $store    = $this->proofStore();

        $deletedFirst = new InterceptedProofStore($store, static function (MultiFactorAuthenticatable $identity, string $id) use ($store): void {
            Assert::assertFalse(Factor::query()->whereKey($id)->exists(), 'The factor must be deleted before the store forgets it.');

            $store->forgetFactor($identity, $id);
        });

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($deletedFirst, $identity, 'web', ProofStoreContract::SESSION, $factor->id);
    }

    /**
     * Not the store's own `record()` and `forget()`.
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
        ProofStoreContract::assertRefusesAProofOfAnotherSignIn($store, $identity, 'web', $store->signIn(), $store->write(...));
        ProofStoreContract::assertRefusesAProofOfAnotherApplication($store, $identity, 'web', $store->signIn(), $store->write(...));
        ProofStoreContract::assertReadsOnlyTheNamedSignIn($store, $identity, 'web', $store->signIn(), static function () use ($store, $identity): string {
            $replacement = $store->signIn();

            $store->begin($identity, 'web', $replacement);

            return $replacement;
        }, $store->write(...));

        $this->addToAssertionCount(1);
    }

    /**
     * Even when the sign-in already held a proof of its own.
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
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    #[\Override]
    protected function proofStore(): ProofStore
    {
        return new SessionProofStore(new Store('contract', new ArraySessionHandler(10)));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function proofStoreIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'store@example.test']);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function otherProofStoreIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'other-store@example.test']);
    }

    /**
     * @return string
     */
    #[\Override]
    protected function proofStoreApplication(): string
    {
        return 'web';
    }

    /**
     * A proof of the other identity's sign-in, begun under the id given.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  string  $otherSession
     * @return void
     */
    private function assertRefusesAProofOfAnotherIdentity(ProofStore $store, string $otherSession = ProofStoreContract::SESSION): void
    {
        ProofStoreContract::assertRefusesAProofOfAnotherIdentity(
            $store,
            $this->proofStoreIdentity(),
            $this->otherProofStoreIdentity(),
            'web',
            ProofStoreContract::SESSION,
            $otherSession,
        );
    }
}
