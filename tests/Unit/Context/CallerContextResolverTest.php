<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `CallerContextResolver`: a pending session is served only an action
 * its credential allows, and never in the guard's user's place; without one the
 * guard's user is served; only a person is served; and what the caller's
 * challenges are bound to.
 *
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
     * Without a pending session the guard's person is served, for any action
     * and for none, on the current application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesTheGuardsPersonWithoutAPendingSession(): void
    {
        $user = $this->signIn();

        foreach ([null, PendingAction::LIST_FACTORS, PendingAction::VERIFY] as $action) {
            $caller = $this->resolver()->resolve($action);

            self::assertSame($user, $caller?->identity);
            self::assertNull($caller->pending);
        }

        self::assertSame('web', $this->resolver()->application(new Caller($user)));
    }

    /**
     * Nobody is served without a signed-in identity, or for one that is not a
     * person.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesNobodyButAPerson(): void
    {
        self::assertNull($this->resolver()->resolve(null));

        $this->actingAs(new NonEloquentIdentity('machine-1', person: false));

        self::assertNull($this->resolver()->resolve(PendingAction::VERIFY));
    }

    /**
     * A bound subject type resolver decides who is a person.
     *
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

        self::assertNull($this->resolver()->resolve(null));
    }

    /**
     * A pending session is served for an action its credential allows, as its
     * own identity, not the guard's user.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesAPendingSessionTheActionsItAllows(): void
    {
        $this->signIn();

        $pending = $this->pending([PendingAction::LIST_FACTORS]);
        $caller  = $this->resolver()->resolve(PendingAction::LIST_FACTORS);

        self::assertSame($pending->identity, $caller?->identity);
        self::assertSame($pending, $caller->pending);
        self::assertSame('admin', $this->resolver()->application($caller));
    }

    /**
     * A pending session is served nothing for an action its credential does not
     * allow, nor for a helper that serves active sessions only; the guard's
     * user is never served in its place.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesAPendingSessionNothingElse(): void
    {
        $this->signIn();
        $this->pending([PendingAction::LIST_FACTORS]);

        self::assertNull($this->resolver()->resolve(PendingAction::VERIFY));
        self::assertNull($this->resolver()->resolve(null));
    }

    /**
     * A pending session of an identity that is not a person is served nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testServesAPendingMachineNothing(): void
    {
        $this->pending([PendingAction::VERIFY], new NonEloquentIdentity('machine-1', person: false));

        self::assertNull($this->resolver()->resolve(PendingAction::VERIFY));
    }

    /**
     * A pending credential that does not validate is refused, not served as the
     * guard's user.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $this->signIn();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->resolver()->resolve(PendingAction::VERIFY);
    }

    /**
     * Without a request there is no pending session to ask about.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutARequestThereIsNoPendingSession(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));
        $this->container()->forgetInstance('request');
        $this->container()->offsetUnset('request');

        self::assertNull($this->resolver()->pending());
    }

    /**
     * A caller's binding names it, its application and its session: the pending
     * session's, or the current sign-in's, and none without one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheCallersSession(): void
    {
        $user = $this->signIn();

        $binding = $this->resolver()->binding(new Caller($user), Purpose::STEP_UP);

        self::assertSame([
            'identity_type' => TestUser::class,
            'identity_key'  => ProofOwner::of($user)->key,
            'application'   => 'web',
            'session_id'    => SignInProofs::SESSION,
            'purpose'       => 'step_up',
        ], $binding?->toArray());

        $pending = $this->pending([PendingAction::VERIFY]);

        self::assertSame('pending-1', $this->resolver()->binding(new Caller($pending->identity, $pending), Purpose::SIGN_IN)?->sessionId);

        $this->container()->make(ProofStore::class)->forget($user, 'web');

        self::assertNull($this->resolver()->binding(new Caller($user), Purpose::SIGN_IN));
    }

    /**
     * The caller is still the one a binding was captured for only while nothing
     * has changed: the action, the sign-in and the purpose are all part of it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testStillAnswersOnlyForTheCapturedBinding(): void
    {
        $user    = $this->signIn();
        $binding = $this->resolver()->binding(new Caller($user), Purpose::STEP_UP);

        self::assertNotNull($binding);
        self::assertSame($user, $this->resolver()->still(PendingAction::VERIFY, $binding)?->identity);

        $this->container()->make(ProofStore::class)->begin($user, 'web', 'sign-in-b');

        self::assertNull($this->resolver()->still(PendingAction::VERIFY, $binding));

        $this->container()->make(ProofStore::class)->begin($user, 'web', $binding->sessionId);

        self::assertNotNull($this->resolver()->still(PendingAction::VERIFY, $binding));

        $this->container()->make(ProofStore::class)->forget($user, 'web');

        self::assertNull($this->resolver()->still(PendingAction::VERIFY, $binding));

        $this->pending([PendingAction::LIST_FACTORS]);

        self::assertNull($this->resolver()->still(PendingAction::VERIFY, $binding));
    }

    /**
     * Sign a person in through the guard, with a sign-in the proof store knows.
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
     * Make every request carry a pending session on the `admin` application, of
     * another person unless given, allowing the actions.
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
        );

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($pending));

        return $pending;
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContextResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): CallerContextResolver
    {
        return $this->container()->make(CallerContextResolver::class);
    }
}
