<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;

/**
 * Registers the factor lifecycle service, the default `LastFactorPolicy`, which
 * refuses removing the last acceptable factor while one is required
 * (`RequiredFactorPolicy`), and the default `SelfServiceRecovery`, which offers
 * none (`NoSelfServiceRecovery`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LifecycleBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the lifecycle service and the default seams.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(LifecycleService::class);
        $app->bindIf(LastFactorPolicy::class, RequiredFactorPolicy::class);
        $app->bindIf(SelfServiceRecovery::class, NoSelfServiceRecovery::class);
    }
}
