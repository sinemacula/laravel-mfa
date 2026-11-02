<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Testing\Seams\StepUpContract;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * The `StepUp` contract kit: a result bound elsewhere, and a failed result, are
 * refused by throwing.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `StepUpContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait StepUpTests
{
    /**
     * A result bound to another session, identity, application or purpose is
     * refused.
     *
     * @return void
     */
    public function testStepUpRefusesAResultOfAnotherBinding(): void
    {
        StepUpContract::assertRefusesAResultOfAnotherBinding($this->stepUp(), $this->stepUpResultOfAnotherBinding());
    }

    /**
     * A failed result is refused.
     *
     * @return void
     */
    public function testStepUpRefusesAFailedResult(): void
    {
        StepUpContract::assertRefusesAFailedResult($this->stepUp());
    }

    /**
     * The step-up under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\StepUp
     */
    abstract protected function stepUp(): StepUp;

    /**
     * A successful result bound to another session than the active one.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    abstract protected function stepUpResultOfAnotherBinding(): VerificationResult;
}
