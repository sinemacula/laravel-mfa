<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\RequestApplication;

/**
 * The application a guard signs an identity in to or out of, for the `Login`
 * and `Logout` listeners; the only other place that reads the request.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $guard
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function of(Container $container, string $guard): string
    {
        $request = $container->bound('request') ? $container->make('request') : null;

        return $request instanceof Request ? RequestApplication::of($container, $request, $guard) : $guard;
    }
}
