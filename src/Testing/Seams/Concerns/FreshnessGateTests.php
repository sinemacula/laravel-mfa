<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Testing\Seams\FreshnessGateContract;

/**
 * The `FreshnessGate` contract kit; each check delegates to
 * `FreshnessGateContract`.
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
     * @return void
     */
    public function testFreshnessGateNeverFindsANameThatIsNoOperationFresh(): void
    {
        FreshnessGateContract::assertANameThatIsNoOperationIsNeverFresh($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * @return void
     */
    public function testFreshnessGateNeverFindsAnOperationWithNoRequirementFresh(): void
    {
        FreshnessGateContract::assertAnOperationWithNoRequirementIsNeverFresh($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * @return void
     */
    public function testFreshnessGateRefusesAnUnboundedRequirement(): void
    {
        FreshnessGateContract::assertAnUnboundedRequirementIsRefused($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * @return void
     */
    public function testFreshnessGateGivesAnOperationThatIsNotFreshNoDeadline(): void
    {
        FreshnessGateContract::assertAnOperationThatIsNotFreshHasNoDeadline($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * @return void
     */
    public function testFreshnessGateGivesAFreshOperationADeadlineAhead(): void
    {
        FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh($this->freshGate(), $this->freshnessCaller(), $this->freshOperation());
    }

    /**
     * @return void
     */
    public function testFreshnessGateHoldsASessionToWhatTheCallerAsks(): void
    {
        FreshnessGateContract::assertTheRequirementAsksWhatTheCallerAsks($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * `freshGate()` must find it fresh for `freshOperation()`.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    abstract protected function freshnessCaller(): CallerContext;

    /**
     * Asked on behalf of a signed-in identity.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    abstract protected function freshnessGate(): FreshnessGate;

    /**
     * Asked on behalf of a session fresh for `freshOperation()`.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    abstract protected function freshGate(): FreshnessGate;

    /**
     * @return string
     */
    abstract protected function freshOperation(): string;
}
