<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `CallerContext`: who an action is served to, built from plain
 * values or, at the one edge that reads a request, from the request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerContext::class)]
#[CoversClass(Caller::class)]
final class CallerContextTest extends TestCase
{
    /**
     * An identity on an active session carries no pending session, and an
     * unknown client when none is given.
     *
     * @return void
     */
    public function testAnIdentityOnAnActiveSession(): void
    {
        $identity = new NonEloquentIdentity('plain-1');
        $caller   = CallerContext::forIdentity($identity, 'web');

        self::assertSame($identity, $caller->identity);
        self::assertNull($caller->pending);
        self::assertSame('web', $caller->application);
        self::assertEquals(ClientContext::unknown(), $caller->client);
    }

    /**
     * A pending session is its own identity's, on its own application.
     *
     * @return void
     */
    public function testAPendingSessionIsItsOwnIdentitysOnItsOwnApplication(): void
    {
        $pending = self::pending();
        $client  = new ClientContext('192.0.2.1');
        $caller  = CallerContext::forPending($pending, $client);

        self::assertSame($pending->identity, $caller->identity);
        self::assertSame($pending, $caller->pending);
        self::assertSame('admin', $caller->application);
        self::assertSame($client, $caller->client);
    }

    /**
     * Nobody carries no identity, on the application.
     *
     * @return void
     */
    public function testNobody(): void
    {
        $caller = CallerContext::nobody('web');

        self::assertNull($caller->identity);
        self::assertNull($caller->pending);
        self::assertSame('web', $caller->application);
    }

    /**
     * A blank application is refused.
     *
     * @return void
     */
    public function testABlankApplicationIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        CallerContext::nobody(' ');
    }

    /**
     * A request's pending session is its caller, ahead of the guard's user.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testARequestsPendingSessionIsItsCaller(): void
    {
        $pending = self::pending();

        $this->actingAs(TestUser::query()->create(['email' => 'guard@example.test']));
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($pending));

        $caller = CallerContext::fromRequest(self::request());

        self::assertSame($pending, $caller->pending);
        self::assertSame($pending->identity, $caller->identity);
        self::assertSame('203.0.113.9', $caller->client->ip);
    }

    /**
     * An invalid pending credential is refused, never served as the guard's
     * user.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnInvalidPendingCredentialIsRefused(): void
    {
        $this->actingAs(TestUser::query()->create(['email' => 'guard@example.test']));
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        CallerContext::fromRequest(self::request());
    }

    /**
     * Without a pending session, the caller is the named guard's user, on the
     * guard's own application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutAPendingSessionTheCallerIsTheGuardsUser(): void
    {
        $user = TestUser::query()->create(['email' => 'guard@example.test']);

        $this->actingAs($user);

        $caller = CallerContext::fromRequest(self::request());

        self::assertSame($user, $caller->identity);
        self::assertNull($caller->pending);
        self::assertSame('web', $caller->application);
        self::assertSame('Agent/1.0', $caller->client->userAgent);

        config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        $admin = CallerContext::fromRequest(self::request(), 'admin');

        self::assertNull($admin->identity);
        self::assertSame('admin', $admin->application);
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
        $request  = self::request();
        $resolver = \Mockery::mock(ApplicationResolver::class);

        $resolver->shouldReceive('resolve')->once()->with($request)->andReturn('mobile');

        $this->container()->instance(ApplicationResolver::class, $resolver);

        self::assertSame('mobile', CallerContext::fromRequest($request)->application);
    }

    /**
     * A guest, or a user this package does not serve, is nobody.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestOrAnotherKindOfUserIsNobody(): void
    {
        self::assertNull(CallerContext::fromRequest(self::request())->identity);

        $this->actingAs(new PlainUser);

        self::assertNull(CallerContext::fromRequest(self::request())->identity);
    }

    /**
     * A caller served gives back the context it was served from.
     *
     * @return void
     */
    public function testACallerGivesBackItsContext(): void
    {
        $identity = new NonEloquentIdentity('plain-1');
        $client   = new ClientContext('192.0.2.1');
        $pending  = self::pending();

        self::assertEquals(CallerContext::forIdentity($identity, 'web', $client), (new Caller($identity, null, 'web', $client))->context());
        self::assertEquals(CallerContext::forPending($pending, $client), (new Caller($pending->identity, $pending, 'admin', $client))->context());
    }

    /**
     * A request from a known client.
     *
     * @return \Illuminate\Http\Request
     */
    private static function request(): Request
    {
        return Request::create('/', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Agent/1.0']);
    }

    /**
     * A pending session on the admin application.
     *
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private static function pending(): PendingContext
    {
        $identity = new NonEloquentIdentity('pending-person');

        return new PendingContext(
            $identity,
            'admin',
            'pending-1',
            SignInProofs::of($identity)->onApplication('admin')->inSession('pending-1')->password(),
            Requirement::none()->withAdditionalVerification(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        );
    }
}
