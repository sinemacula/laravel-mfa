<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Tests for `ProofService`: the current identity's proofs are read through the
 * bound store on the current application, and a proof is recorded bound to the
 * identity's current sign-in and verification generation, or not at all without
 * a sign-in.
 *
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
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * A guest has no proofs, and the store is not asked.
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

        self::assertSame([], $this->service()->proofs());

        $store->shouldNotHaveReceived('proofs');
    }

    /**
     * The current identity's proofs are the store's, on the current
     * application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReadsTheCurrentIdentitysProofsOnTheCurrentApplication(): void
    {
        $user  = $this->user();
        $proof = self::proof();

        $this->actingAs($user);

        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('proofs')->once()->with($user, 'web')->andReturn([$proof]);

        $this->container()->instance(ProofStore::class, $store);

        self::assertSame([$proof], $this->service()->proofs());
    }

    /**
     * Without an application resolver, the application is the default guard's
     * name.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheApplicationIsTheDefaultGuardsName(): void
    {
        self::assertSame('web', $this->service()->application());

        config()->set('auth.defaults.guard', 'admin');

        self::assertSame('admin', $this->service()->application());
    }

    /**
     * A bound application resolver names the application for the request.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABoundResolverNamesTheApplication(): void
    {
        $request = $this->container()->make(Request::class);

        $resolver = \Mockery::mock(ApplicationResolver::class);
        $resolver->shouldReceive('resolve')->once()->with($request)->andReturn('mobile');

        $this->container()->instance(ApplicationResolver::class, $resolver);

        self::assertSame('mobile', $this->service()->application());
    }

    /**
     * An identity has a sign-in once one begins, and not before.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasASignInOnceOneBegins(): void
    {
        $user = $this->user();

        self::assertFalse($this->service()->hasSignIn($user));

        $this->container()->make(ProofStore::class)->begin($user, 'sign-in-1');

        self::assertTrue($this->service()->hasSignIn($user));
    }

    /**
     * An identity with no sign-in records nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRecordsNothingWithoutASignIn(): void
    {
        $user = $this->user();

        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('currentSession')->once()->with($user)->andReturnNull();
        $store->shouldNotReceive('record');

        $this->container()->instance(ProofStore::class, $store);

        self::assertNull($this->service()->record($user, ProofKind::RECOVERY_CODE, 'backup_code', null, null, Purpose::STEP_UP));

        $store->shouldNotHaveReceived('record');
    }

    /**
     * A recorded proof is bound to the identity, the current application, its
     * current sign-in and the given purpose, made now under its current
     * generation, observing nothing, and the store keeps it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecordsAProofBoundToTheCurrentSignIn(): void
    {
        CarbonImmutable::setTestNow('2026-11-01T10:00:00.000000+00:00');

        $user    = $this->user();
        $store   = $this->container()->make(ProofStore::class);
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-1');

        $store->begin($user, 'sign-in-1');

        VerificationGeneration::advance($user);

        $proof = $this->service()->record($user, ProofKind::ADDITIONAL_FACTOR, 'totp', $channel, 'factor-1', Purpose::STEP_UP);

        self::assertNotNull($proof);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proof->kind);
        self::assertSame('totp', $proof->method);
        self::assertSame($channel, $proof->channel);
        self::assertSame('factor-1', $proof->reference);
        self::assertEquals(ObservedProperties::none(), $proof->properties);
        self::assertTrue(CarbonImmutable::now()->equalTo($proof->provedAt));
        self::assertSame([
            'identity_type' => TestUser::class,
            'identity_key'  => '7',
            'application'   => 'web',
            'session_id'    => 'sign-in-1',
            'purpose'       => 'step_up',
        ], $proof->binding->toArray());
        self::assertSame(1, $proof->generation);
        self::assertNull($proof->challengeId);
        self::assertSame([$proof->toArray()], array_map(static fn (Proof $kept): array => $kept->toArray(), $store->proofs($user, 'web')));
    }

    /**
     * Forgetting a factor stops its proofs counting through the store.
     *
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
     * Resolve the proof service from the container.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): ProofService
    {
        return $this->container()->make(ProofService::class);
    }

    /**
     * A test user, never saved.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', 7);

        return $user;
    }
}
