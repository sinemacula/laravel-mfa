<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerContextResolver::class)]
#[CoversClass(Caller::class)]
final class CallerContextResolverTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesTheGuardsPersonWithoutAPendingSession(): void
    {
        $user = $this->signIn();

        foreach ([null, PendingAction::LIST_FACTORS, PendingAction::VERIFY] as $action) {
            $caller = $this->resolver()->resolve(Callers::current(), $action);

            self::assertSame($user, $caller?->identity);
            self::assertNull($caller->pending);
        }

        self::assertSame('web', $this->resolver()->application(new Caller($user, null, 'web')));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesNobodyButAPerson(): void
    {
        self::assertNull($this->resolver()->resolve(Callers::current(), null));

        $this->actingAs(new NonEloquentIdentity('machine-1', person: false));

        self::assertNull($this->resolver()->resolve(Callers::current(), PendingAction::VERIFY));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheBoundSubjectTypeResolverDecides(): void
    {
        $this->signIn();

        $resolver = \Mockery::mock(SubjectTypeResolver::class);
        $resolver->shouldReceive('isPerson')->andReturnFalse();

        $this->container()->instance(SubjectTypeResolver::class, $resolver);

        self::assertNull($this->resolver()->resolve(Callers::current(), null));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesAPendingSessionTheActionsItAllows(): void
    {
        $this->signIn();

        $pending = $this->pending([PendingAction::LIST_FACTORS]);
        $caller  = $this->resolver()->resolve(Callers::current(), PendingAction::LIST_FACTORS);

        self::assertSame($pending->identity, $caller?->identity);
        self::assertSame($pending, $caller->pending);
        self::assertSame('admin', $this->resolver()->application($caller));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesAPendingSessionNothingElse(): void
    {
        $this->signIn();
        $this->pending([PendingAction::LIST_FACTORS]);

        self::assertNull($this->resolver()->resolve(Callers::current(), PendingAction::VERIFY));
        self::assertNull($this->resolver()->resolve(Callers::current(), null));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesAPendingMachineNothing(): void
    {
        $this->pending([PendingAction::VERIFY], new NonEloquentIdentity('machine-1', person: false));

        self::assertNull($this->resolver()->resolve(Callers::current(), PendingAction::VERIFY));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $this->signIn();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->resolver()->resolve(Callers::current(), PendingAction::VERIFY);
    }

    /**
     * No request or pending resolver is asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNobodyIsServedNothing(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        foreach ([null, PendingAction::VERIFY] as $action) {
            self::assertNull($this->resolver()->resolve(CallerContext::nobody('web'), $action));
        }
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheCallersSession(): void
    {
        $user = $this->signIn();

        $binding = $this->resolver()->binding(new Caller($user, null, 'web'), Purpose::STEP_UP);

        self::assertSame([
            'identity_type' => TestUser::class,
            'identity_key'  => ProofOwner::of($user)->key,
            'application'   => 'web',
            'session_id'    => SignInProofs::SESSION,
            'purpose'       => 'step_up',
        ], $binding?->toArray());

        $pending = $this->pending([PendingAction::VERIFY]);

        self::assertSame('pending-1', $this->resolver()->binding(new Caller($pending->identity, $pending, $pending->application), Purpose::SIGN_IN)?->sessionId);

        $this->container()->make(ProofStore::class)->forget($user, 'web');

        self::assertNull($this->resolver()->binding(new Caller($user, null, 'web'), Purpose::SIGN_IN));
    }

    /**
     * The action, the sign-in and the purpose are all part of the binding.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testStillAnswersOnlyForTheCapturedBinding(): void
    {
        $user    = $this->signIn();
        $binding = $this->resolver()->binding(new Caller($user, null, 'web'), Purpose::STEP_UP);

        $caller = new Caller($user, null, 'web');

        self::assertNotNull($binding);
        self::assertSame($user, $this->resolver()->still($caller, PendingAction::VERIFY, $binding)?->identity);

        $this->container()->make(ProofStore::class)->begin($user, 'web', 'sign-in-b');

        self::assertNull($this->resolver()->still($caller, PendingAction::VERIFY, $binding));

        $this->container()->make(ProofStore::class)->begin($user, 'web', $binding->sessionId);

        self::assertNotNull($this->resolver()->still($caller, PendingAction::VERIFY, $binding));

        $this->container()->make(ProofStore::class)->forget($user, 'web');

        self::assertNull($this->resolver()->still($caller, PendingAction::VERIFY, $binding));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testStillRevalidatesAPendingCaller(): void
    {
        $pending = $this->pending([PendingAction::VERIFY]);
        $caller  = new Caller($pending->identity, $pending, $pending->application);
        $binding = $this->resolver()->binding($caller, Purpose::SIGN_IN);

        self::assertNotNull($binding);
        self::assertSame($pending, $this->resolver()->still($caller, PendingAction::VERIFY, $binding)?->pending);
        self::assertNull($this->resolver()->still($caller, PendingAction::LIST_FACTORS, $binding));

        $this->pending([PendingAction::LIST_FACTORS]);

        self::assertNull($this->resolver()->still($caller, PendingAction::VERIFY, $binding));

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver);

        self::assertNull($this->resolver()->still($caller, PendingAction::VERIFY, $binding));
    }

    /**
     * With a sign-in the proof store knows.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'guard@example.test']);

        $this->actingAs($user);

        $this->container()->make(ProofStore::class)->begin($user, 'web', SignInProofs::SESSION);

        return $user;
    }

    /**
     * Every request carries a pending session on `admin`, of another person
     * unless given.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @param  ?\Tests\Fixtures\Identities\NonEloquentIdentity  $identity
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private function pending(array $actions, ?NonEloquentIdentity $identity = null): PendingContext
    {
        $identity ??= new NonEloquentIdentity('pending-person');

        $pending = new PendingContext(
            $identity,
            'admin',
            'pending-1',
            SignInProofs::of($identity)->onApplication('admin')->inSession('pending-1')->password(),
            Requirement::none()->withAdditionalVerification(),
            $actions,
            CarbonImmutable::now()->addMinutes(10),
        );

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($pending));

        return $pending;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\CallerContextResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): CallerContextResolver
    {
        return $this->container()->make(CallerContextResolver::class);
    }
}
