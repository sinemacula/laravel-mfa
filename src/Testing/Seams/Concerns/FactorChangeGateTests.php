<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Testing\Seams\FactorChangeGateContract;

/**
 * The `FactorChangeGate` contract kit. The hooks arrange each session; the gate
 * is asked inside a storage transaction, as the package asks it.
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
     * @return void
     */
    public function testFactorChangeGateAllowsEveryChangeFromAFreshSession(): void
    {
        foreach (FactorChange::cases() as $change) {
            FactorChangeGateContract::assertAFreshChangeIsAllowed($this->factorChangeGate(), $this->freshChange($change));
        }
    }

    /**
     * @return void
     */
    public function testFactorChangeGateRefusesEveryChangeFromAStaleSession(): void
    {
        foreach (FactorChange::cases() as $change) {
            FactorChangeGateContract::assertAStaleChangeIsRefused($this->factorChangeGate(), $this->staleChange($change));
        }
    }

    /**
     * @return void
     */
    public function testFactorChangeGateNeverLetsAFactorAuthorizeItsOwnRemoval(): void
    {
        FactorChangeGateContract::assertAFactorNeverAuthorizesItsOwnRemoval($this->factorChangeGate(), $this->removalSteppedUpOnlyWithTheFactor());
    }

    /**
     * @return void
     */
    public function testFactorChangeGateIsBoundByTheConfiguredRequirement(): void
    {
        FactorChangeGateContract::assertTheConfiguredRequirementBinds($this->factorChangeGate(), $this->changeBeyondTheConfiguredRequirement());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate
     */
    abstract protected function factorChangeGate(): FactorChangeGate;

    /**
     * From a session fresh enough for the change.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function freshChange(FactorChange $change): FactorChangeRequest;

    /**
     * From a session not fresh enough for the change.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function staleChange(FactorChange $change): FactorChangeRequest;

    /**
     * A removal whose only step-up used that factor, while the identity has
     * another confirmed factor.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function removalSteppedUpOnlyWithTheFactor(): FactorChangeRequest;

    /**
     * Fresh by the gate's own policy, but carrying a configured requirement the
     * session does not meet.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    abstract protected function changeBeyondTheConfiguredRequirement(): FactorChangeRequest;
}
