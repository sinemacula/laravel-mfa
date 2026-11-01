<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;

/**
 * Registers the default `CombinationPolicy`, which classifies combinations of
 * proofs from what they observed. An application that is stricter, or that
 * trusts an external provider's reported methods, rebinds the contract in its
 * own service provider.
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
     * Register the default combination policy.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(CombinationPolicy::class, DefaultCombinationPolicy::class);
    }
}
