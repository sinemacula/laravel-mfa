<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * The application a request is for through a guard: what a bound
 * `GuardApplicationResolver` names for the request and the guard, what any
 * other bound `ApplicationResolver` names for the request, or else the guard's
 * name. `CallerContext::fromRequest()` and the sign-in and sign-out listeners
 * both ask here, so a proof begun at sign-in is bound to the application its
 * caller is served on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequestApplication
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The application the request is for through the guard.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function of(Container $container, Request $request, string $guard): string
    {
        if (!$container->bound(ApplicationResolver::class)) {
            return $guard;
        }

        $resolver = $container->make(ApplicationResolver::class);

        return $resolver instanceof GuardApplicationResolver ? $resolver->resolveForGuard($request, $guard) : $resolver->resolve($request);
    }
}
