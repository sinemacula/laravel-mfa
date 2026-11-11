<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * The application a request is for through a guard, falling back to the guard's
 * name. Shared by `CallerContext::fromRequest()` and the sign-in listeners so a
 * proof begun at sign-in binds to the caller's application.
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
