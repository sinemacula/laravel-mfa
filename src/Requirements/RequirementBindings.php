<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;

/**
 * Registers the requirement service and the default `MfaPolicy`, which enforces
 * nothing beyond the identity's own preference. Consumers who need external
 * enforcement (organisation-level, role-level, feature-flag-level) rebind the
 * `MfaPolicy` contract in their own service provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequirementBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the requirement service and the default policy.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(MfaPolicy::class, NullMfaPolicy::class);
        $app->singleton(RequirementService::class);
    }
}
