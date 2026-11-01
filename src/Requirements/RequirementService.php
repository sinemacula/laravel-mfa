<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Decides whether the current identity must use multi-factor authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the policy is read from. */
        private Container $container,
    ) {}

    /**
     * Determine whether the current identity should use multi-factor
     * authentication.
     *
     * Returns true when the identity's own preference requests MFA, or when the
     * bound `MfaPolicy` enforces it externally. The default policy
     * (`NullMfaPolicy`) always returns false, so standalone apps behave purely
     * on the identity's own `shouldUseMultiFactor()` preference.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function shouldUse(): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return false;
        }

        if ($identity->shouldUseMultiFactor()) {
            return true;
        }

        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaPolicy $policy */
        $policy = $this->container->make(MfaPolicy::class);

        return $policy->shouldEnforce($identity);
    }
}
