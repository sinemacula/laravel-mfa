<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http;

use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Routing\Router;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\Middleware\ExemptFromMfa;
use SineMacula\Laravel\Mfa\Support\PackageDefault;

/**
 * Registers the default `SessionTransition` and the `mfa` and `mfa.exempt`
 * aliases. The gate runs straight after authentication in the middleware
 * priority, so `['mfa', 'auth:api']` judges the identity `auth:api` selects.
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
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        PackageDefault::bind($app, SessionTransition::class, MiddlewareSessionTransition::class);
    }

    /**
     * Prioritises the gate now if the kernel is already resolved, as it is
     * before an application boots, otherwise once it is.
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

        $router->aliasMiddleware('mfa', EnsureMfaRequirementIsMet::class);
        $router->aliasMiddleware('mfa.exempt', ExemptFromMfa::class);

        $app->afterResolving(HttpKernel::class, self::prioritizeGate(...));

        if (!$app->resolved(HttpKernel::class)) {
            return;
        }

        self::prioritizeGate($app->make(HttpKernel::class));
    }

    /**
     * @param  mixed  $kernel
     * @return void
     */
    private static function prioritizeGate(mixed $kernel): void
    {
        if (!$kernel instanceof Kernel) {
            return;
        }

        $kernel->addToMiddlewarePriorityAfter(AuthenticatesRequests::class, EnsureMfaRequirementIsMet::class);
    }
}
