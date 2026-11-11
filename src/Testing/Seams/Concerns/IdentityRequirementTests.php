<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;

/**
 * The `IdentityRequirement` contract kit; each check delegates to
 * `RequirementSeamContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait IdentityRequirementTests
{
    /**
     * Another identity is asked in between.
     *
     * @return void
     */
    public function testIdentityRequirementKeepsNoStateBetweenCalls(): void
    {
        $requirement = $this->identityRequirement();
        $identity    = $this->requiringIdentity();
        $other       = $this->otherRequiringIdentity();
        $application = $this->requirementApplication();

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(
            static fn () => $requirement->requirementFor($identity, $application),
            static fn () => $requirement->requirementFor($other, $application),
        );
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\IdentityRequirement
     */
    abstract protected function identityRequirement(): IdentityRequirement;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function requiringIdentity(): MultiFactorAuthenticatable;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function otherRequiringIdentity(): MultiFactorAuthenticatable;

    /**
     * @return string
     */
    abstract protected function requirementApplication(): string;
}
