<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;

/**
 * Registers the default `PasskeyGateway`, which makes passkeys unavailable
 * until an authentication layer, or the application, binds its own
 * (`UnavailablePasskeyGateway`), and the change gate, assertions and
 * association records built on it. The package refuses to boot with an
 * application that enables the `passkey` type while the default is bound.
 *
 * Nothing here keeps state between calls, and each is built when it is asked
 * for, on the application serving at the time.
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
     * Register the default passkey gateway, the change gate, the assertions and
     * the association records.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bind(PasskeyGateway::class, UnavailablePasskeyGateway::class);
        $app->bind(PasskeyAssociations::class);
        $app->bind(PasskeyAssertions::class);
        $app->bind(PasskeyChangeGate::class);
    }
}
