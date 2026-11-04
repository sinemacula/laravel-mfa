<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Testing\Seams\FactorChangeGateContract;

/**
 * The `FactorChangeGate` contract kit: every change is allowed from a session
 * fresh enough for it, a grant ending in the future, and refused by throwing
 * from one that is not; a factor never authorises its own removal; and the
 * requirement the application configures binds the gate.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks, which arrange each session and return the request for it; each
 * check delegates to `FactorChangeGateContract`. The gate is asked inside a
 * transaction on the storage connection the test opens, as the package asks it.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait FactorChangeGateTests
{
    /**
     * Every change is allowed from a session fresh enough for it.
     *
     * @return void
     */
    public function testFactorChangeGateAllowsEveryChangeFromAFreshSession(): void
    {
        foreach (FactorChange::cases() as $change) {
            FactorChangeGateContract::assertAFreshChangeIsAllowed($this->factorChangeGate(), $this->freshChange($change));
        }
    }

    /**
     * Every change is refused from a session that is not fresh enough for it.
     *
     * @return void
     */
    public function testFactorChangeGateRefusesEveryChangeFromAStaleSession(): void
    {
        foreach (FactorChange::cases() as $change) {
            FactorChangeGateContract::assertAStaleChangeIsRefused($this->factorChangeGate(), $this->staleChange($change));
        }
    }

    /**
     * A factor never authorises its own removal.
     *
     * @return void
     */
    public function testFactorChangeGateNeverLetsAFactorAuthorizeItsOwnRemoval(): void
    {
        FactorChangeGateContract::assertAFactorNeverAuthorizesItsOwnRemoval($this->factorChangeGate(), $this->removalSteppedUpOnlyWithTheFactor());
    }

    /**
     * The requirement the application configures binds the gate.
     *
     * @return void
     */
    public function testFactorChangeGateIsBoundByTheConfiguredRequirement(): void
    {
        FactorChangeGateContract::assertTheConfiguredRequirementBinds($this->factorChangeGate(), $this->changeBeyondTheConfiguredRequirement());
    }

    /**
     * The gate under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate
     */
    abstract protected function factorChangeGate(): FactorChangeGate;

    /**
     * The request for the change, from a session arranged to be fresh enough
     * for it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function freshChange(FactorChange $change): FactorChangeRequest;

    /**
     * The request for the change, from a session arranged not to be fresh
     * enough for it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function staleChange(FactorChange $change): FactorChangeRequest;

    /**
     * The request to remove a factor, from a session whose only step-up was
     * made with that factor, while the identity has another confirmed factor.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function removalSteppedUpOnlyWithTheFactor(): FactorChangeRequest;

    /**
     * The request for a change from a session fresh enough by the gate's own
     * policy, carrying a configured requirement the session does not meet.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function changeBeyondTheConfiguredRequirement(): FactorChangeRequest;
}
