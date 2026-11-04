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

/**
 * Registers the default `SessionTransition`, which leaves a session left short
 * to the `mfa` middleware (`MiddlewareSessionTransition`), and the package's
 * middleware under short aliases, so consumers can reference them as `'mfa'`
 * and `'mfa.exempt'` in their route files without importing class names. The
 * gate is placed straight after authentication in the middleware priority, so
 * `['mfa', 'auth:api']` judges the identity `auth:api` selects.
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
     * Register the default session transition.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(SessionTransition::class, MiddlewareSessionTransition::class);
    }

    /**
     * Register the middleware aliases with the router, and place the gate after
     * authentication in the HTTP kernel's priority: now if the kernel is
     * resolved already, as it is before an application boots, otherwise when it
     * is.
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
     * Place the gate after authentication in the priority of a kernel that has
     * one.
     *
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
