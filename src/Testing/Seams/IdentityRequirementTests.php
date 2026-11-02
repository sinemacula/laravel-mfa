<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The `IdentityRequirement` contract kit: it keeps no state between calls.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `RequirementSeamContract`.
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
     * The same identity answers the same requirement, whatever another identity
     * was asked in between.
     *
     * @return void
     */
    public function testIdentityRequirementKeepsNoStateBetweenCalls(): void
    {
        $requirement = $this->identityRequirement();
        $identity    = $this->requiringIdentity();
        $other       = $this->otherRequiringIdentity();
        $application = $this->requirementApplication();

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(static fn () => $requirement->requirementFor($identity, $application), static fn () => $requirement->requirementFor($other, $application));
    }

    /**
     * The requirement under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\IdentityRequirement
     */
    abstract protected function identityRequirement(): IdentityRequirement;

    /**
     * An identity asked about.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function requiringIdentity(): MultiFactorAuthenticatable;

    /**
     * Another identity, asked about in between.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function otherRequiringIdentity(): MultiFactorAuthenticatable;

    /**
     * The application asked about.
     *
     * @return string
     */
    abstract protected function requirementApplication(): string;
}
