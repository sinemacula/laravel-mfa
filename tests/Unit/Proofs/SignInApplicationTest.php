<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Proofs\SignInApplication;
use Tests\Fixtures\Context\GuardPortalResolver;
use Tests\TestCase;

/**
 * Tests for `SignInApplication`: the application a guard signs an identity in
 * to is its own name, unless a bound resolver names one for the request,
 * through the guard when it is a guard application resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInApplication::class)]
final class SignInApplicationTest extends TestCase
{
    /**
     * Without a resolver, a guard names its own application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardNamesItsOwnApplication(): void
    {
        self::assertSame('admin', SignInApplication::of($this->container(), 'admin'));
    }

    /**
     * A bound resolver names the application for the request being served.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABoundResolverNamesTheApplication(): void
    {
        $request  = $this->container()->make(Request::class);
        $resolver = \Mockery::mock(ApplicationResolver::class);

        $resolver->shouldReceive('resolve')->once()->with($request)->andReturn('mobile');

        $this->container()->instance(ApplicationResolver::class, $resolver);

        self::assertSame('mobile', SignInApplication::of($this->container(), 'admin'));
    }

    /**
     * A guard application resolver names the application through the event's
     * guard, not the one it would name without it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardApplicationResolverNamesTheApplicationThroughTheGuard(): void
    {
        $this->container()->instance(ApplicationResolver::class, new GuardPortalResolver);

        self::assertSame('admin-portal', SignInApplication::of($this->container(), 'admin'));
    }

    /**
     * With no request being served, a resolver is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithNoRequestTheResolverIsNotAsked(): void
    {
        $resolver = \Mockery::mock(ApplicationResolver::class);

        $resolver->shouldNotReceive('resolve');

        $this->container()->instance(ApplicationResolver::class, $resolver);
        $this->container()->forgetInstance('request');
        $this->container()->offsetUnset('request');

        self::assertSame('admin', SignInApplication::of($this->container(), 'admin'));
    }
}
