<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Contracts\Foundation\Application;

/**
 * Registers the verification service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerificationBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the verification service with the container.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(VerificationService::class);
    }
}
