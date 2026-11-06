<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Testing\Seams\FreshnessGateContract;

/**
 * The `FreshnessGate` contract kit: a name that is not an operation's, and an
 * operation with no requirement, are never fresh, a caller's requirement with
 * no maximum age is refused, and a deadline is ahead and means fresh.
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
        FreshnessGateContract::assertANameThatIsNoOperationIsNeverFresh($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * An operation with no requirement from either side is never fresh.
     *
     * @return void
     */
    public function testFreshnessGateNeverFindsAnOperationWithNoRequirementFresh(): void
    {
        FreshnessGateContract::assertAnOperationWithNoRequirementIsNeverFresh($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * A caller's requirement with no maximum age is refused.
     *
     * @return void
     */
    public function testFreshnessGateRefusesAnUnboundedRequirement(): void
    {
        FreshnessGateContract::assertAnUnboundedRequirementIsRefused($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * An operation that is not fresh has no deadline.
     *
     * @return void
     */
    public function testFreshnessGateGivesAnOperationThatIsNotFreshNoDeadline(): void
    {
        FreshnessGateContract::assertAnOperationThatIsNotFreshHasNoDeadline($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * A session fresh for an operation has a deadline ahead of it.
     *
     * @return void
     */
    public function testFreshnessGateGivesAFreshOperationADeadlineAhead(): void
    {
        FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh($this->freshGate(), $this->freshnessCaller(), $this->freshOperation());
    }

    /**
     * The requirement the gate holds a session to asks at least what the caller
     * asks.
     *
     * @return void
     */
    public function testFreshnessGateHoldsASessionToWhatTheCallerAsks(): void
    {
        FreshnessGateContract::assertTheRequirementAsksWhatTheCallerAsks($this->freshnessGate(), $this->freshnessCaller());
    }

    /**
     * The caller whose freshness the gates judge: the fresh gate must find it
     * fresh for the fresh operation.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    abstract protected function freshnessCaller(): CallerContext;

    /**
     * The gate under test, asked on behalf of a signed-in identity.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    abstract protected function freshnessGate(): FreshnessGate;

    /**
     * The gate under test, asked on behalf of a session fresh for the operation
     * `freshOperation()` names.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    abstract protected function freshGate(): FreshnessGate;

    /**
     * An operation the session `freshGate()` asks for is fresh for.
     *
     * @return string
     */
    abstract protected function freshOperation(): string;
}
