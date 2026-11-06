<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\RequestApplication;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Proofs\SignInApplication;
use Tests\Fixtures\Context\GuardPortalResolver;
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\TestCase;

/**
 * Tests for `RequestApplication`: the application a request is for through a
 * guard is the guard's name, or what a bound resolver names, through the guard
 * when it is a guard application resolver; and a caller and a sign-in on the
 * same guard name the same one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestApplication::class)]
final class RequestApplicationTest extends TestCase
{
    /**
     * Without a resolver, the application is the guard's name.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutAResolverTheApplicationIsTheGuardsName(): void
    {
        self::assertSame('admin', RequestApplication::of($this->container(), Request::create('/'), 'admin'));
    }

    /**
     * A resolver that knows no guard names the request's application whatever
     * the guard.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolverWithoutTheGuardNamesTheRequestsApplication(): void
    {
        $this->container()->instance(ApplicationResolver::class, new HeaderApplicationResolver);

        self::assertSame('mobile', RequestApplication::of($this->container(), HeaderApplicationResolver::requestFor('mobile'), 'admin'));
    }

    /**
     * A guard application resolver is asked through the guard, and its answer
     * without one is not used.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardApplicationResolverIsAskedThroughTheGuard(): void
    {
        $this->container()->instance(ApplicationResolver::class, new GuardPortalResolver);

        self::assertSame('admin-portal', RequestApplication::of($this->container(), Request::create('/'), 'admin'));
        self::assertSame('web-portal', RequestApplication::of($this->container(), Request::create('/'), 'web'));
    }

    /**
     * The caller of a request through a guard and a sign-in on that guard name
     * the same application, with each kind of resolver and with none, so a
     * proof begun at sign-in is bound to the application its caller is served
     * on.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACallerAndASignInOnTheSameGuardNameTheSameApplication(): void
    {
        config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        $request = HeaderApplicationResolver::requestFor('mobile');

        $this->container()->instance('request', $request);

        foreach ([null, new HeaderApplicationResolver, new GuardPortalResolver] as $resolver) {

            if ($resolver !== null) {
                $this->container()->instance(ApplicationResolver::class, $resolver);
            }

            foreach (['web', 'admin'] as $guard) {
                self::assertSame(SignInApplication::of($this->container(), $guard), CallerContext::fromRequest($request, $guard, $this->container())->application);
            }
        }

        self::assertSame('admin-portal', SignInApplication::of($this->container(), 'admin'));
    }
}
