<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
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
     * A guard names its own application without a resolver, and the bound
     * resolver's application with one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardsApplicationIsItsNameUnlessAResolverNamesOne(): void
    {
        self::assertSame('admin', $this->service()->applicationFor('admin'));

        $resolver = \Mockery::mock(ApplicationResolver::class);
        $resolver->shouldReceive('resolve')->once()->andReturn('mobile');

        $this->container()->instance(ApplicationResolver::class, $resolver);

        self::assertSame('mobile', $this->service()->applicationFor('admin'));
    }

    /**
     * Beginning a sign-in for a guard begins it on the guard's application
     * under a fresh id, and ending it forgets only that application's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBeginsAndEndsASignInOnTheGuardsApplication(): void
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
     * The generation a proof would be stamped with is the identity's current
     * one once it has a sign-in on the current application, and `null` before,
     * without reading the generation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGenerationToStampNeedsASignInOnTheCurrentApplication(): void
    {
        $user  = $this->user();
        $store = $this->container()->make(ProofStore::class);

        VerificationGeneration::advance($user);

        $store->begin($user, 'admin', 'sign-in-1');

        DB::connection()->enableQueryLog();

        self::assertNull($this->service()->generationFor($user));
        self::assertSame([], DB::connection()->getQueryLog());

        $store->begin($user, 'web', 'sign-in-2');

        self::assertSame(1, $this->service()->generationFor($user));
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
        $store->shouldReceive('currentSession')->once()->with($user, 'web')->andReturnNull();
        $store->shouldNotReceive('record');

        $this->container()->instance(ProofStore::class, $store);

        self::assertNull($this->service()->record($user, 0, ProofKind::RECOVERY_CODE, 'recovery_code', null, null, Purpose::STEP_UP));

        $store->shouldNotHaveReceived('record');
    }

    /**
     * A recorded proof is bound to the identity, the current application, its
     * current sign-in and the given purpose, made now under the generation it
     * was given, observing nothing, and the store keeps it.
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

        $store->begin($user, 'web', 'sign-in-1');

        VerificationGeneration::advance($user);

        $proof = $this->service()->record($user, 1, ProofKind::ADDITIONAL_FACTOR, 'totp', $channel, 'factor-1', Purpose::STEP_UP);

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
     * A proof recorded inside a transaction on the storage connection is kept
     * only once that transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofMadeInATransactionIsKeptOnceItCommits(): void
    {
        $user  = $this->user();
        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, 'web', 'sign-in-1');

        DB::beginTransaction();

        self::assertNotNull($this->service()->record($user, 0, ProofKind::RECOVERY_CODE, 'recovery_code', null, null, Purpose::STEP_UP));
        self::assertCount(0, $store->proofs($user, 'web'));

        DB::commit();

        self::assertCount(1, $store->proofs($user, 'web'));
    }

    /**
     * A proof recorded inside a transaction that rolls back is never kept, so a
     * verification undone with it leaves no proof behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofMadeInATransactionThatRollsBackIsNeverKept(): void
    {
        $user  = $this->user();
        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, 'web', 'sign-in-1');

        DB::beginTransaction();

        $this->service()->record($user, 0, ProofKind::RECOVERY_CODE, 'recovery_code', null, null, Purpose::STEP_UP);

        DB::rollBack();

        self::assertSame([], $store->proofs($user, 'web'));
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
