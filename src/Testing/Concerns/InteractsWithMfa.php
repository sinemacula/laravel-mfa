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
     * Act as the identity with a sign-in the proof store holds, verified at the
     * time and exactly the level given, for the guard and application given or
     * the default ones, replacing any earlier sign-in there.
     *
     * This is a fixture for gating routes, not a statement that the
     * application's sign-in can reach the level. It dispatches no `Login` and
     * no MFA event, enrols no factor, and bypasses no inactivity check,
     * re-enrolment obligation or stricter requirement, and it needs the
     * package's migrations for the identity's verification generation.
     *
     * The application chooses where the proofs go, not what the next request
     * resolves. A guard with a context of its own is arranged by its own helper
     * first: a guard already holding the identity is left as it is.
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
