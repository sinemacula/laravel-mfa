<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\ReplacingProofStore;
use Tests\TestCase;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofService::class)]
final class ProofServiceTest extends TestCase
{
    use BuildsProofs, RefreshDatabase;

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * The store is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestHasNoProofs(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldNotReceive('proofs');

        $this->container()->instance(ProofStore::class, $store);

        self::assertSame([], $this->service()->proofs(Callers::current()));

        $store->shouldNotHaveReceived('proofs');
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReadsTheCallersProofsOnItsApplication(): void
    {
        $user  = $this->user();
        $proof = self::proof();

        $this->actingAs($user);

        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('currentSession')->once()->with($user, 'web')->andReturn('sign-in-1');
        $store->shouldReceive('proofs')->once()->with($user, 'web', 'sign-in-1')->andReturn([$proof]);

        $this->container()->instance(ProofStore::class, $store);

        self::assertSame([$proof], $this->service()->proofs(Callers::current()));
    }

    /**
     * The store is not asked for any.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIdentityWithNoSignInHasNoProofs(): void
    {
        $user = $this->user();

        $this->actingAs($user);

        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('currentSession')->once()->with($user, 'web')->andReturnNull();
        $store->shouldNotReceive('proofs');

        $this->container()->instance(ProofStore::class, $store);

        self::assertSame([], $this->service()->proofs(Callers::current()));
    }

    /**
     * Replaced between reading which sign-in is current and reading its proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function testASignInReplacedBetweenTheReadsLendsNothing(): void
    {
        $user  = $this->user();
        $store = $this->container()->make(ProofStore::class);

        $this->actingAs($user);

        $store->begin($user, 'web', 'sign-in-1');
        $store->record($user, $this->proofOn($user, 'sign-in-1'));

        $this->container()->instance(ProofStore::class, new ReplacingProofStore($store, function (ProofStore $wrapped) use ($user): void {
            $wrapped->begin($user, 'web', 'sign-in-2');
            $wrapped->record($user, $this->proofOn($user, 'sign-in-2'));
        }));

        self::assertSame([], $this->service()->proofs(Callers::current()));
        self::assertCount(1, $store->proofs($user, 'web', 'sign-in-2'));
    }

    /**
     * Begun under a fresh id; ending it forgets only that application's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBeginsAndEndsASignInOnTheApplication(): void
    {
        $user  = $this->user();
        $store = $this->container()->make(ProofStore::class);

        $this->service()->beginSignIn($user, 'web');
        $this->service()->beginSignIn($user, 'admin');

        $web = $store->currentSession($user, 'web');

        self::assertIsString($web);
        self::assertIsString($store->currentSession($user, 'admin'));
        self::assertNotSame($web, $store->currentSession($user, 'admin'));

        $this->service()->endSignIn($user, 'admin');

        self::assertSame($web, $store->currentSession($user, 'web'));
        self::assertNull($store->currentSession($user, 'admin'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetFactorDelegatesToTheStore(): void
    {
        $user = $this->user();

        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('forgetFactor')->once()->with($user, 'factor-1');

        $this->container()->instance(ProofStore::class, $store);

        $this->service()->forgetFactor($user, 'factor-1');

        $store->shouldHaveReceived('forgetFactor')->once();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): ProofService
    {
        return $this->container()->make(ProofService::class);
    }

    /**
     * Made a minute ago on the `web` sign-in.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function proofOn(TestUser $user, string $session): Proof
    {
        $owner = ProofOwner::of($user);

        return self::proof([
            'provedAt'   => CarbonImmutable::now()->subMinute(),
            'binding'    => new ProofBinding($owner->type, $owner->key, 'web', $session, Purpose::STEP_UP),
            'generation' => 0,
        ]);
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', 7);

        return $user;
    }
}
