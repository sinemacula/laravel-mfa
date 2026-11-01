<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;

/**
 * The IP address an attempt is charged to: the request being served, as
 * resolved through the application's trusted proxies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequestIp
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The IP address of the request being served, or `null` outside a request.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function resolve(Container $container): ?string
    {
        $request = $container->bound('request') ? $container->make('request') : null;

        return $request instanceof Request ? $request->ip() : null;
    }
}
