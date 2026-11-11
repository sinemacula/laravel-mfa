<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;

/**
 * Binds the lifecycle service and the default last-factor and self-service
 * recovery seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LifecycleBindings
{
    /**
     * Static only.
     */
    private function __construct() {}

    /**
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
