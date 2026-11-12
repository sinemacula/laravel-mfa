<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Support\PackageDefault;

/**
 * Binds the default `CombinationPolicy` only if the application has not bound
 * its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AssuranceBindings
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
        PackageDefault::bind($app, CombinationPolicy::class, DefaultCombinationPolicy::class);
    }
}
