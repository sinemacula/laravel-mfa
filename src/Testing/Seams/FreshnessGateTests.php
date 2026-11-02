<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;

/**
 * The `FreshnessGate` contract kit: a name that is not an operation's, and an
 * operation with no requirement, are never fresh, and a caller's requirement
 * with no maximum age is refused.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `FreshnessGateContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait FreshnessGateTests
{
    /**
     * A name that is not an operation's is never fresh.
     *
     * @return void
     */
    public function testFreshnessGateNeverFindsANameThatIsNoOperationFresh(): void
    {
        FreshnessGateContract::assertANameThatIsNoOperationIsNeverFresh($this->freshnessGate());
    }

    /**
     * An operation with no requirement from either side is never fresh.
     *
     * @return void
     */
    public function testFreshnessGateNeverFindsAnOperationWithNoRequirementFresh(): void
    {
        FreshnessGateContract::assertAnOperationWithNoRequirementIsNeverFresh($this->freshnessGate());
    }

    /**
     * A caller's requirement with no maximum age is refused.
     *
     * @return void
     */
    public function testFreshnessGateRefusesAnUnboundedRequirement(): void
    {
        FreshnessGateContract::assertAnUnboundedRequirementIsRefused($this->freshnessGate());
    }

    /**
     * The gate under test, asked on behalf of a signed-in identity.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    abstract protected function freshnessGate(): FreshnessGate;
}
