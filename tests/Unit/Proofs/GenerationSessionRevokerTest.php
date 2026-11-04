<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\Enums\ProofStoreFlaw;
use Tests\Fixtures\Seams\FlawedProofStore;
use Tests\TestCase;

/**
 * Tests for `GenerationSessionRevoker`, which revokes by advancing the
 * identity's verification generation: the other sessions' proofs stop counting,
 * the current sign-in's are recorded again under exactly the generation
 * advanced to once the change commits, and a change that rolls back revokes
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GenerationSessionRevoker::class)]
final class GenerationSessionRevokerTest extends TestCase
{
    /** @var \SineMacula\Laravel\Mfa\Proofs\SessionProofStore The store of the person's other device. */
    private SessionProofStore $otherDevice;

    /** @var \Tests\Fixtures\Identities\TestUser The person, signed in on this device. */
    private TestUser $user;

    /**
     * Sign the person in on this device and verify them on another.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'revoked@example.test']);

        $this->user        = $user;
        $this->otherDevice = new SessionProofStore(new Store('other-device', new ArraySessionHandler(10)));

        $this->actingAs($user);

        $this->store()->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $this->store()->record(SignInProofs::of($user)->password());
        $this->store()->record(SignInProofs::of($user)->totp());

        $this->otherDevice->begin($user, SignInProofs::APPLICATION, 'other-sign-in');
        $this->otherDevice->record(SignInProofs::of($user)->inSession('other-sign-in')->totp());
    }

    /**
     * A factor's removal stops the other device's proofs counting, and the
     * current sign-in keeps its own, under the generation advanced to, leaving
     * the current session for the package to judge again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAFactorKeepsTheCurrentSignInsProofs(): void
    {
        $revocation = $this->removeFactor();

        self::assertFalse($revocation->judgedCurrent);
        self::assertNull($revocation->completion);

        self::assertSame([], $this->otherDevice->proofs($this->user, SignInProofs::APPLICATION));
        self::assertSame(['password', 'totp'], $this->methods());
        self::assertSame([1, 1], array_map(static fn (Proof $proof): int => $proof->generation, $this->store()->proofs($this->user, SignInProofs::APPLICATION)));
    }

    /**
     * Revoking every session stops every proof counting, the current sign-in's
     * included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAllStopsEveryProofCounting(): void
    {
        $this->revoker()->revokeAll($this->user);

        self::assertSame([], $this->otherDevice->proofs($this->user, SignInProofs::APPLICATION));
        self::assertSame([], $this->methods());
        self::assertSame(1, VerificationGeneration::current($this->user));
    }

    /**
     * A revocation in a change that rolls back revokes nothing and records
     * nothing again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackRevocationRevokesNothing(): void
    {
        DB::beginTransaction();

        $this->removeFactor();

        DB::rollBack();

        self::assertCount(1, $this->otherDevice->proofs($this->user, SignInProofs::APPLICATION));
        self::assertSame(['password', 'totp'], $this->methods());
        self::assertSame(0, VerificationGeneration::current($this->user));
    }

    /**
     * A reset after a factor's removal in the same change wins: the current
     * sign-in's proofs are recorded again under the generation the first
     * revocation advanced to, which the reset left behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALaterResetInTheSameChangeWins(): void
    {
        DB::transaction(function (): void {
            $this->removeFactor();
            $this->revoker()->revokeAll($this->user);
        });

        self::assertSame([], $this->methods());
        self::assertSame(2, VerificationGeneration::current($this->user));
    }

    /**
     * A sign-in replaced before the change commits is not given the proofs of
     * the one before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInReplacedBeforeTheCommitIsNotRestamped(): void
    {
        DB::transaction(function (): void {
            $this->removeFactor();
            $this->store()->begin($this->user, SignInProofs::APPLICATION, 'sign-in-2');
        });

        self::assertSame('sign-in-2', $this->store()->currentSession($this->user, SignInProofs::APPLICATION));
        self::assertSame([], $this->methods());
    }

    /**
     * A sign-in replaced before the change commits is not given the proofs of
     * the one before, even by a store that would record a proof bound to
     * another sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInReplacedBeforeTheCommitIsNotGivenTheProofsBefore(): void
    {
        $store = new FlawedProofStore(ProofStoreFlaw::ACCEPTS_ANY_SIGN_IN);

        $this->container()->instance(ProofStore::class, $store);

        $store->begin($this->user, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record(SignInProofs::of($this->user)->password());
        $store->record(SignInProofs::of($this->user)->totp());

        DB::transaction(function () use ($store): void {
            $this->removeFactor();
            $store->begin($this->user, SignInProofs::APPLICATION, 'sign-in-2');
        });

        self::assertSame('sign-in-2', $store->currentSession($this->user, SignInProofs::APPLICATION));
        self::assertSame([], $store->proofs($this->user, SignInProofs::APPLICATION));
    }

    /**
     * Two removals in one change leave the current sign-in to verify again: the
     * second finds nothing counting to keep.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoRevocationsInOneChangeLeaveTheCurrentSignInToVerifyAgain(): void
    {
        DB::transaction(function (): void {
            $this->removeFactor();
            $this->removeFactor();
        });

        self::assertSame([], $this->methods());
    }

    /**
     * Without a sign-in nothing is recorded again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutASignInNothingIsKept(): void
    {
        $this->store()->forget($this->user, SignInProofs::APPLICATION);

        $this->removeFactor();

        self::assertNull($this->store()->currentSession($this->user, SignInProofs::APPLICATION));
        self::assertSame(1, VerificationGeneration::current($this->user));
    }

    /**
     * The proofs made with the removed factor are not kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRemovedFactorsProofsAreNotKept(): void
    {
        $this->revoker()->factorRemoved($this->user, 'factor-totp', SignInProofs::SESSION);

        self::assertSame(['password'], $this->methods());
    }

    /**
     * A removal named as made from a sign-in that is not the current one keeps
     * nothing of the current one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalFromAnotherSignInKeepsNothing(): void
    {
        $this->revoker()->factorRemoved($this->user, 'removed-factor', 'other-sign-in');

        self::assertSame([], $this->methods());
        self::assertSame(1, VerificationGeneration::current($this->user));
    }

    /**
     * Remove a factor the current sign-in's proofs were not made with, from the
     * current sign-in.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \Throwable
     */
    private function removeFactor(): RemovalRevocation
    {
        return $this->revoker()->factorRemoved($this->user, 'removed-factor', SignInProofs::SESSION);
    }

    /**
     * The methods of the current sign-in's proofs that count, oldest first.
     *
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function methods(): array
    {
        return array_map(static fn (Proof $proof): string => $proof->method, $this->store()->proofs($this->user, SignInProofs::APPLICATION));
    }

    /**
     * The bound proof store.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): ProofStore
    {
        return $this->container()->make(ProofStore::class);
    }

    /**
     * The revoker under test.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function revoker(): GenerationSessionRevoker
    {
        return $this->container()->make(GenerationSessionRevoker::class);
    }
}
