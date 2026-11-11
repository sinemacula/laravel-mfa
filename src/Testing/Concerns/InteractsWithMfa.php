<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Concerns;

use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Testing\VerifiedSignIn;

/**
 * Lets a test act as an identity verified at a given time and level.
 *
 * It needs no particular base test case: Testbench's does not extend Laravel's.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait InteractsWithMfa
{
    /**
     * Act as the identity with a sign-in verified at `$at` and exactly
     * `$level`, replacing any earlier sign-in for the guard and application.
     *
     * A fixture for gating routes: it dispatches no event, enrols no factor
     * through the default recorder, bypasses no inactivity, re-enrolment or
     * stricter requirement check, and needs the package's migrations.
     * `$application` picks where the proofs go, not what the next request
     * resolves. A guard already holding the identity is left as it is.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?\DateTimeInterface  $at
     * @param  ?string  $guard
     * @param  ?string  $application
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function actingAsVerified(
        MultiFactorAuthenticatable $identity,
        AssuranceLevel $level = AssuranceLevel::AAL2,
        ?\DateTimeInterface $at = null,
        ?string $guard = null,
        ?string $application = null,
    ): static {
        Container::getInstance()->make(VerifiedSignIn::class)->act($identity, $level, $at, $guard, $application);

        return $this;
    }
}
