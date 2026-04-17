<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Policies;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;

/**
 * Null MFA policy.
 *
 * The default `MfaPolicy` binding. Always returns `false`, deferring entirely
 * to the identity's own `shouldUseMultiFactor()` preference. Consumers who need
 * external enforcement (organisation-level, role-level, feature-flag-level)
 * bind their own policy implementation in place of this default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class NullMfaPolicy implements MfaPolicy
{
    /**
     * Determine whether MFA should be enforced for the given identity. Always
     * `false` for the null policy.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function shouldEnforce(Authenticatable $identity): bool
    {
        return false;
    }
}
