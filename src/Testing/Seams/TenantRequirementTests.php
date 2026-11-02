<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;

/**
 * The `TenantRequirement` contract kit: it keeps no state between calls.
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
trait TenantRequirementTests
{
    /**
     * The same tenant answers the same requirement, whatever another tenant was
     * asked in between.
     *
     * @return void
     */
    public function testTenantRequirementKeepsNoStateBetweenCalls(): void
    {
        $requirement = $this->tenantRequirement();
        $identity    = $this->tenantIdentity();
        $application = $this->tenantApplication();

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(static fn () => $requirement->requirementFor($identity, $application, 'contract-tenant'), static fn () => $requirement->requirementFor($identity, $application, 'contract-other-tenant'));
    }

    /**
     * The requirement under test.
     *
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
     * The application asked about.
     *
     * @return string
     */
    abstract protected function tenantApplication(): string;
}
