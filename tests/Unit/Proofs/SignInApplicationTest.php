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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInApplication::class)]
final class SignInApplicationTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardNamesItsOwnApplication(): void
    {
        self::assertSame('admin', SignInApplication::of($this->container(), 'admin'));
    }

    /**
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
     * Not the one it would name without the guard.
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
