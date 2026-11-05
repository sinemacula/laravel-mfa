<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ProofStoreTests;
use SineMacula\Laravel\Mfa\Testing\Seams\ProofStoreContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\SignInRowsProofStore;
use Tests\TestCase;

/**
 * The `ProofStore` kit over a store backed by sign-ins it did not begin, each
 * holding its first factor already: the test arranges each sign-in and voids
 * the proofs the store's own way, through the kit's hooks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreContract::class)]
final class ProofStoreKitHooksTest extends TestCase
{
    use ProofStoreTests;

    /** @var \Tests\Fixtures\Seams\SignInRowsProofStore The store under test. */
    private SignInRowsProofStore $store;

    /** @var list<string> The sign-ins the kit asked for. */
    private array $signIns = [];

    /**
     * Set up the store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new SignInRowsProofStore;
    }

    /**
     * The kit begins only the sign-in the test arranged, once a check.
     *
     * @return void
     */
    public function testTheKitBeginsTheSignInTheTestArranged(): void
    {
        $this->testProofStoreForgetsASignInsProofsWithIt();

        self::assertSame(['row-1'], $this->signIns);
    }

    /**
     * A store whose proofs outlive the void is still rejected.
     *
     * @return void
     */
    public function testTheKitRejectsAVoidThatVoidsNothing(): void
    {
        $identity = $this->proofStoreIdentity();

        $this->expectException(AssertionFailedError::class);

        ProofStoreContract::assertVoidedProofsStopCounting($this->store, $identity, 'web', $this->store->arrange($identity, 'web'), static function (): void {});
    }

    /**
     * A void is not checked on an arranged proof that never counted, even when
     * the sign-in already held a proof of its own.
     *
     * @return void
     */
    public function testTheKitRefusesAVoidWhenTheArrangedProofNeverCounted(): void
    {
        $identity = $this->proofStoreIdentity();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A proof of the current sign-in must count before the proofs are voided.');

        ProofStoreContract::assertVoidedProofsStopCounting(
            $this->store,
            $identity,
            'web',
            $this->store->arrange($identity, 'web'),
            $this->store->void(...),
            static function (): void {},
        );
    }

    /**
     * The store under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    #[\Override]
    protected function proofStore(): ProofStore
    {
        return $this->store;
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
        return TestUser::query()->firstOrCreate(['email' => 'rows@example.test']);
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

    /**
     * Arrange a sign-in in the store, as signing in through the layer would.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     */
    protected function proofStoreSignIn(MultiFactorAuthenticatable $identity, string $application): string
    {
        $session = $this->store->arrange($identity, $application);

        $this->signIns[] = $session;

        return $session;
    }

    /**
     * Void the proofs the store's own way.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    protected function voidProofStoreProofs(MultiFactorAuthenticatable $identity): void
    {
        $this->store->void();
    }
}
