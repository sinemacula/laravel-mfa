<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Identity requirement contract.
 *
 * What the identity itself requires whatever the application's setting, for
 * example a further factor for platform staff. An empty requirement adds
 * nothing to the others.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentityRequirement
{
    /**
     * The identity's own requirement on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement;
}
