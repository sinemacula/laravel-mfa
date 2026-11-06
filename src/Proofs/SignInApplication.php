<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;

/**
 * The application a guard signs an identity in to or out of, for the sign-in
 * and sign-out listeners: the edge where Laravel's `Login` and `Logout` events
 * arrive, and the only place outside `Context\CallerContext::fromRequest()`
 * that reads the request. It is the one a bound `ApplicationResolver` names for
 * the request being served, or else the guard's name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInApplication
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The application the guard acts for on the request being served.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $guard
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function of(Container $container, string $guard): string
    {
        $request = $container->bound('request') ? $container->make('request') : null;

        if ($request instanceof Request && $container->bound(ApplicationResolver::class)) {
            return $container->make(ApplicationResolver::class)->resolve($request);
        }

        return $guard;
    }
}
