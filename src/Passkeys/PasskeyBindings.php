<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Support\PackageDefault;

/**
 * Binds `UnavailablePasskeyGateway` until an authentication layer binds its
 * own, and the services built on the gateway.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PasskeyBindings
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
        PackageDefault::bind($app, PasskeyGateway::class, UnavailablePasskeyGateway::class);
        $app->bindIf(PasskeyAssociations::class);
        $app->bindIf(PasskeyAssertions::class);
        $app->bindIf(PasskeyChangeGate::class);
    }
}
