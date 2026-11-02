<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionTransitionContract;

/**
 * The `SessionTransition` contract kit: returning a session to pending returns,
 * or refuses by throwing a `RuntimeException`.
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
     * Returning a session to pending returns, or refuses by throwing.
     *
     * @return void
     */
    public function testSessionTransitionReturnsOrRefusesByThrowing(): void
    {
        SessionTransitionContract::assertReturnsOrRefusesByThrowing($this->sessionTransition(), $this->transitionIdentity(), $this->transitionApplication());
    }

    /**
     * The transition under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    abstract protected function sessionTransition(): SessionTransition;

    /**
     * An identity with a current session.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function transitionIdentity(): MultiFactorAuthenticatable;

    /**
     * The application its session is on.
     *
     * @return string
     */
    abstract protected function transitionApplication(): string;
}
