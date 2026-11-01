<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Events\Dispatcher;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Http\HttpBindings;
use SineMacula\Laravel\Mfa\Http\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Http\Middleware\SkipMfa;
use Tests\TestCase;

/**
 * Tests for `HttpBindings`: the middleware are registered under their short
 * aliases.
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
     * The middleware are aliased as `mfa` and `mfa.skip`, and nothing else is
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

        self::assertSame(['mfa' => RequireMfa::class, 'mfa.skip' => SkipMfa::class], $router->getMiddleware());
    }
}
