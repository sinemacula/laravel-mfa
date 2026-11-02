<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An active tenant resolver with a fixed answer, as an adapter reading a
 * session's validated context would give.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedActiveTenant implements ActiveTenantResolver
{
    /**
     * Constructor.
     *
     * @param  ?string  $tenant
     */
    public function __construct(

        /** The tenant named, or `null` for none. */
        private ?string $tenant,
    ) {}

    /**
     * The fixed tenant.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        return $this->tenant;
    }
}
