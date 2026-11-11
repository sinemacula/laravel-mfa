<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Testing\Seams\StepUpContract;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * The `StepUp` contract kit; each check delegates to `StepUpContract`.
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
     * @return void
     */
    public function testStepUpRefusesAResultOfAnotherBinding(): void
    {
        StepUpContract::assertRefusesAResultOfAnotherBinding($this->stepUp(), $this->stepUpCaller(), $this->stepUpResultOfAnotherBinding());
    }

    /**
     * @return void
     */
    public function testStepUpRefusesAFailedResult(): void
    {
        StepUpContract::assertRefusesAFailedResult($this->stepUp(), $this->stepUpCaller());
    }

    /**
     * A caller on an active session, whose own result would be accepted.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    abstract protected function stepUpCaller(): CallerContext;

    /**
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
