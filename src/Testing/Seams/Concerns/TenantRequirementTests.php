<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;

/**
 * The `TenantRequirement` contract kit; each check delegates to
 * `RequirementSeamContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait TenantRequirementTests
{
    /**
     * Another tenant is asked in between.
     *
     * @return void
     */
    public function testTenantRequirementKeepsNoStateBetweenCalls(): void
    {
        $requirement = $this->tenantRequirement();
        $identity    = $this->tenantIdentity();
        $application = $this->tenantApplication();

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(
            static fn () => $requirement->requirementFor($identity, $application, 'contract-tenant'),
            static fn () => $requirement->requirementFor($identity, $application, 'contract-other-tenant'),
        );
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     */
    abstract protected function tenantRequirement(): TenantRequirement;

    /**
     * An identity with an active tenant.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function tenantIdentity(): MultiFactorAuthenticatable;

    /**
     * @return string
     */
    abstract protected function tenantApplication(): string;
}
