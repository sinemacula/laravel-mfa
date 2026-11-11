<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Seams;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;

/**
 * Default bindings for seams that read nothing of the package; an adapter or
 * the application rebinds them in its own provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeamBindings
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
        $app->bindIf(Reauthenticator::class, RefusingReauthenticator::class);
    }
}
