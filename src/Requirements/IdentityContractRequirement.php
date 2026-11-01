<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The default `IdentityRequirement`: what the identity model itself answers
 * from `requiresAdditionalFactor()`, in every application, and nothing when it
 * answers `null`, as the `HasFactors` trait does by default. An authentication
 * layer's adapter rebinds the contract to answer from that layer instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IdentityContractRequirement implements IdentityRequirement
{
    /**
     * The identity's own requirement on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
    {
        return $identity->requiresAdditionalFactor() ?? Requirement::none();
    }
}
