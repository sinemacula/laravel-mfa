<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionTransitionContract;

/**
 * The `SessionTransition` contract kit; each check delegates to
 * `SessionTransitionContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait SessionTransitionTests
{
    /**
     * @return void
     */
    public function testSessionTransitionReturnsOrRefusesByThrowing(): void
    {
        SessionTransitionContract::assertReturnsOrRefusesByThrowing($this->sessionTransition(), $this->sessionChange(...));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    abstract protected function sessionTransition(): SessionTransition;

    /**
     * The change, on an active session arranged afresh for it; the kit supplies
     * the package's assessment.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\SessionChange
     */
    abstract protected function sessionChange(FactorChangeMade $change): SessionChange;
}
