<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ProofStoreTests;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\LayerWrittenProofStore;
use Tests\TestCase;

/**
 * The `ProofStore` kit over a store whose proofs and sign-ins only an
 * authentication layer writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreContract::class)]
final class ProofStoreLayerHooksTest extends TestCase
{
    use ProofStoreTests;

    /** @var \Tests\Fixtures\Seams\LayerWrittenProofStore The store under test. */
    private LayerWrittenProofStore $store;

    /** @var list<string> What the kit asked of the layer, in order. */
    private array $asked = [];

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new LayerWrittenProofStore;
    }

    /**
     * @return void
     */
    public function testTheKitWritesAndSignsOutThroughTheLayer(): void
    {
        $this->testProofStoreForgetsASignInsProofsWithIt();

        self::assertSame(['write FIRST_FACTOR', 'sign out'], $this->asked);
    }

    /**
     * @return void
     */
    public function testTheKitNamesTheFactorTheTestEnrolled(): void
    {
        $this->testProofStoreStopsCountingAForgottenFactor();

        self::assertSame(['enrol', 'write FIRST_FACTOR', 'write ADDITIONAL_FACTOR', 'forget factor-1'], $this->asked);
    }

    /**
     * Without the hooks the proofs recorded through the store never count, and
     * the kit says so before forgetting the factor.
     *
     * @return void
     */
    public function testTheKitRefusesProofsThatNeverCounted(): void
    {
        $identity = $this->proofStoreIdentity();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Both proofs must count before the factor is forgotten.');

        ProofStoreContract::assertForgettingAFactorStopsItsProofsCounting($this->store, $identity, 'web', $this->store->signIn());
    }

    /**
     * Without the hooks, voiding is not checked.
     *
     * @return void
     */
    public function testTheKitRefusesAVoidOfProofsThatNeverCounted(): void
    {
        $identity = $this->proofStoreIdentity();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of the current sign-in must count before the proofs are voided.');

        ProofStoreContract::assertVoidedProofsStopCounting($this->store, $identity, 'web', $this->store->signIn(), static function (): void {});
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    #[\Override]
    protected function proofStore(): ProofStore
    {
        return $this->store;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function proofStoreIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'layer@example.test']);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function otherProofStoreIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'other-layer@example.test']);
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     */
    protected function proofStoreSignIn(MultiFactorAuthenticatable $identity, string $application): string
    {
        return $this->store->signIn();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return string
     */
    protected function replaceProofStoreSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session): string
    {
        $replacement = $this->store->signIn();

        $this->store->begin($identity, $application, $replacement);

        return $replacement;
    }

    /**
     * The layer voids proofs on a reset by signing out.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    protected function voidProofStoreProofs(MultiFactorAuthenticatable $identity): void
    {
        $this->store->signOut();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    protected function arrangeProofStoreProof(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session, Proof $proof): void
    {
        $this->asked[] = 'write ' . $proof->kind->name;

        $this->store->write($proof);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  string  $factor
     * @return void
     */
    protected function forgetProofStoreFactor(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session, string $factor): void
    {
        $this->asked[] = 'forget ' . $factor;

        $store->forgetFactor($identity, $factor);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    protected function endProofStoreSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->asked[] = 'sign out';

        $this->store->signOut();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    protected function proofStoreFactor(MultiFactorAuthenticatable $identity): string
    {
        $this->asked[] = 'enrol';

        return $this->store->enrol();
    }
}
