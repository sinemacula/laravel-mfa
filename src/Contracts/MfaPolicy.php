<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * MFA policy contract.
 *
 * Implemented by app-level policies that enforce MFA beyond the identity's own
 * `shouldUseMultiFactor()` preference — e.g. an organisation-aware policy that
 * mandates MFA for every member, or a role-aware policy that mandates it for
 * every admin.
 *
 * The MFA manager consults the bound policy in `shouldUse()` after the
 * identity. The package ships a no-op default (`NullMfaPolicy`); consumers
 * needing external enforcement bind their own implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface MfaPolicy
{
    /**
     * Determine whether MFA should be enforced for the given identity,
     * independent of the identity's own preference.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    public function shouldEnforce(Authenticatable $identity): bool;
}
