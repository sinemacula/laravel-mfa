<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * MFA policy contract.
 *
 * Implemented by app-level policies that enforce multi-factor
 * authentication on identities beyond the identity's own
 * `shouldUseMultiFactor()` preference. For example, an
 * organisation-aware policy may require MFA for every member of an
 * organisation that mandates it; a role-aware policy may require
 * MFA for every admin regardless of individual preference.
 *
 * The MFA manager consults the bound policy in `shouldUse()` after
 * consulting the identity. The package ships a no-op default
 * (`NullMfaPolicy`); consumers who need external enforcement bind
 * their own implementation against this contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface MfaPolicy
{
    /**
     * Determine whether MFA should be enforced for the given
     * identity, independent of the identity's own preference.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    public function shouldEnforce(Authenticatable $identity): bool;
}
