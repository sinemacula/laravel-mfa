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
 * Revokes by advancing the generation, then records the current sign-in's
 * proofs again once the change commits.
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
        $this->store()->record($user, SignInProofs::of($user)->password());
        $this->store()->record($user, SignInProofs::of($user)->totp());

        $this->otherDevice->begin($user, SignInProofs::APPLICATION, 'other-sign-in');
        $this->otherDevice->record($user, SignInProofs::of($user)->inSession('other-sign-in')->totp());
    }

    /**
     * The other device's proofs stop counting; the current session is left for
     * the package to judge again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAFactorKeepsTheCurrentSignInsProofs(): void
    {
        $revocation = $this->removeFactor();

        self::assertFalse($revocation->judgedCurrent);
        self::assertNull($revocation->completion());

        self::assertSame([], $this->otherDevice->proofs($this->user, SignInProofs::APPLICATION, 'other-sign-in'));
        self::assertSame(['password', 'totp'], $this->methods());
        $kept = $this->store()->proofs($this->user, SignInProofs::APPLICATION, SignInProofs::SESSION);

        self::assertSame([1, 1], array_map(static fn (Proof $proof): int => $proof->generation, $kept));
    }

    /**
     * The current sign-in's included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAllStopsEveryProofCounting(): void
    {
        $this->revoker()->revokeAll($this->user);

        self::assertSame([], $this->otherDevice->proofs($this->user, SignInProofs::APPLICATION, 'other-sign-in'));
        self::assertSame([], $this->methods());
        self::assertSame(1, VerificationGeneration::current($this->user));
    }

    /**
     * Nothing is recorded again either.
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

        self::assertCount(1, $this->otherDevice->proofs($this->user, SignInProofs::APPLICATION, 'other-sign-in'));
        self::assertSame(['password', 'totp'], $this->methods());
        self::assertSame(0, VerificationGeneration::current($this->user));
    }

    /**
     * The proofs are recorded again under the generation the first revocation
     * advanced to, which the reset left behind.
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
     * Even by a store that would record a proof bound to another sign-in.
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
        $store->record($this->user, SignInProofs::of($this->user)->password());
        $store->record($this->user, SignInProofs::of($this->user)->totp());

        DB::transaction(function () use ($store): void {
            $this->removeFactor();
            $store->begin($this->user, SignInProofs::APPLICATION, 'sign-in-2');
        });

        self::assertSame('sign-in-2', $store->currentSession($this->user, SignInProofs::APPLICATION));
        self::assertSame([], $store->proofs($this->user, SignInProofs::APPLICATION, 'sign-in-2'));
    }

    /**
     * The second finds nothing counting to keep.
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
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRemovedFactorsProofsAreNotKept(): void
    {
        $this->revoker()->factorRemoved($this->user, 'factor-totp', 'web', SignInProofs::SESSION);

        self::assertSame(['password'], $this->methods());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalFromAnotherSignInKeepsNothing(): void
    {
        $this->revoker()->factorRemoved($this->user, 'removed-factor', 'web', 'other-sign-in');

        self::assertSame([], $this->methods());
        self::assertSame(1, VerificationGeneration::current($this->user));
    }

    /**
     * Once it is current, not whichever sign-in the store answers afterwards.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProofsKeptAreReadForTheSignInNamed(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('currentSession')->with($this->user, 'web')->andReturn(SignInProofs::SESSION);
        $store->shouldReceive('proofs')->once()->with($this->user, 'web', SignInProofs::SESSION)->andReturn([]);

        $this->container()->instance(ProofStore::class, $store);

        $this->removeFactor();

        $store->shouldHaveReceived('proofs')->once()->with($this->user, 'web', SignInProofs::SESSION);
        self::assertSame(1, VerificationGeneration::current($this->user));
    }

    /**
     * A factor the current sign-in's proofs were not made with.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \Throwable
     */
    private function removeFactor(): RemovalRevocation
    {
        return $this->revoker()->factorRemoved($this->user, 'removed-factor', 'web', SignInProofs::SESSION);
    }

    /**
     * Methods of the current sign-in's counting proofs, oldest first.
     *
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function methods(): array
    {
        return array_map(static fn (Proof $proof): string => $proof->method, $this->store()->proofs($this->user, SignInProofs::APPLICATION, SignInProofs::SESSION));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): ProofStore
    {
        return $this->container()->make(ProofStore::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function revoker(): GenerationSessionRevoker
    {
        return $this->container()->make(GenerationSessionRevoker::class);
    }
}
