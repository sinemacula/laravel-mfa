<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use SineMacula\Laravel\Mfa\Http\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Http\Middleware\SkipMfa;

/**
 * Registers the package's middleware under short aliases, so consumers can
 * reference them as `'mfa'` and `'mfa.skip'` in their route files without
 * importing class names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HttpBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the middleware aliases with the router.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function boot(Application $app): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $app->make(Router::class);

        $router->aliasMiddleware('mfa', RequireMfa::class);
        $router->aliasMiddleware('mfa.skip', SkipMfa::class);
    }
}
