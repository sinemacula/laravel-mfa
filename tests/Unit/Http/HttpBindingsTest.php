<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Http\HttpBindings;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\Middleware\ExemptFromMfa;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use Tests\TestCase;

/**
 * Tests for `HttpBindings`: the middleware are registered under their short
 * aliases, and the gate runs straight after authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HttpBindings::class)]
final class HttpBindingsTest extends TestCase
{
    /**
     * The middleware are aliased as `mfa` and `mfa.exempt`, and nothing else is
     * registered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAliasesTheMiddleware(): void
    {
        $router = new Router(new Dispatcher($this->container()), $this->container());

        $this->container()->instance(Router::class, $router);

        HttpBindings::boot($this->container());

        self::assertSame(['mfa' => EnsureMfaRequirementIsMet::class, 'mfa.exempt' => ExemptFromMfa::class], $router->getMiddleware());
    }

    /**
     * The session transition defaults to leaving the session to the `mfa`
     * middleware, shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheMiddlewareSessionTransitionByDefault(): void
    {
        self::assertInstanceOf(MiddlewareSessionTransition::class, $this->container()->make(SessionTransition::class));
        self::assertTrue($this->container()->isShared(SessionTransition::class));
    }

    /**
     * A kernel resolved after the package boots places the gate straight after
     * authentication, once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testPlacesTheGateInAKernelResolvedLater(): void
    {
        $app = $this->applicationWithAKernel();

        HttpBindings::boot($app);

        self::assertFalse($app->resolved(HttpKernel::class));

        $this->assertTheGateFollowsAuthentication($app->make(HttpKernel::class));
    }

    /**
     * A kernel resolved before the package boots, as an application's is, has
     * the gate placed at once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testPlacesTheGateInAKernelResolvedAlready(): void
    {
        $app    = $this->applicationWithAKernel();
        $kernel = $app->make(HttpKernel::class);

        HttpBindings::boot($app);

        $this->assertTheGateFollowsAuthentication($kernel);
    }

    /**
     * A kernel that is not the framework's has no priority to place it in, and
     * is left alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesAnyOtherKernelAlone(): void
    {
        $app    = $this->applicationWithAKernel();
        $kernel = self::createStub(HttpKernel::class);

        $app->instance(HttpKernel::class, $kernel);

        HttpBindings::boot($app);

        self::assertTrue($app->resolved(HttpKernel::class));
    }

    /**
     * Assert the gate is in the kernel's priority once, straight after
     * authentication.
     *
     * @param  mixed  $kernel
     * @return void
     */
    private function assertTheGateFollowsAuthentication(mixed $kernel): void
    {
        self::assertInstanceOf(Kernel::class, $kernel);

        $priority = $kernel->getMiddlewarePriority();
        $position = array_search(AuthenticatesRequests::class, $priority, true);

        self::assertIsInt($position);
        self::assertSame(EnsureMfaRequirementIsMet::class, $priority[$position + 1] ?? null);
        self::assertCount(1, array_keys($priority, EnsureMfaRequirementIsMet::class, true));
    }

    /**
     * An application of its own whose kernel has not been resolved, leaving the
     * container the rest of the test case uses in place.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function applicationWithAKernel(): Application
    {
        $app = new Application(sys_get_temp_dir());

        Container::setInstance($this->container());

        $router = new Router(new Dispatcher($app), $app);

        $app->instance(Router::class, $router);
        $app->singleton(HttpKernel::class, static fn (Application $app): Kernel => new Kernel($app, $router));

        return $app;
    }
}
