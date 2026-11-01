<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;

/**
 * Registers the default `SmsGateway`, which fails loud on first use; consumers
 * who enable the SMS driver rebind the contract to an implementation that talks
 * to their chosen SMS provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the default SMS gateway.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(SmsGateway::class, NullSmsGateway::class);
    }
}
