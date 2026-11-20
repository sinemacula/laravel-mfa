<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Support\FactorStateLocks;

/**
 * Registers the factor services and the factor state locks a request holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorBindings
{
    /**
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(FactorService::class);
        $app->scopedIf(FactorStateLocks::class);
    }
}
