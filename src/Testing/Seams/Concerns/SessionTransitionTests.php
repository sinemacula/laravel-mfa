<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionTransitionContract;

/**
 * The `SessionTransition` contract kit: judging a session again after each
 * change to its factors, with a shortfall and without, returns, or refuses by
 * throwing a `RuntimeException`.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `SessionTransitionContract`.
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
     * Judging a session after each change returns, or refuses by throwing.
     *
     * @return void
     */
    public function testSessionTransitionReturnsOrRefusesByThrowing(): void
    {
        SessionTransitionContract::assertReturnsOrRefusesByThrowing($this->sessionTransition(), $this->sessionChange(...));
    }

    /**
     * The transition under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    abstract protected function sessionTransition(): SessionTransition;

    /**
     * The change, made on an active session arranged afresh for it: an identity
     * signed in on an application, the sign-in's session id, and the factor the
     * change was made to. The kit gives it the package's assessment.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\SessionChange
     */
    abstract protected function sessionChange(FactorChangeMade $change): SessionChange;
}
