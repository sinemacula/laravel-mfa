<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * The `PendingCompletion` contract kit: a result bound elsewhere, and a failed
 * result, are refused by throwing.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `PendingCompletionContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait PendingCompletionTests
{
    /**
     * A result bound to another session, identity, application or purpose is
     * refused.
     *
     * @return void
     */
    public function testPendingCompletionRefusesAResultOfAnotherBinding(): void
    {
        PendingCompletionContract::assertRefusesAResultOfAnotherBinding($this->pendingCompletion(), $this->pendingContext(), $this->resultOfAnotherBinding());
    }

    /**
     * A failed result is refused.
     *
     * @return void
     */
    public function testPendingCompletionRefusesAFailedResult(): void
    {
        PendingCompletionContract::assertRefusesAFailedResult($this->pendingCompletion(), $this->pendingContext());
    }

    /**
     * The completion under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingCompletion
     */
    abstract protected function pendingCompletion(): PendingCompletion;

    /**
     * A pending session the completion knows.
     *
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    abstract protected function pendingContext(): PendingContext;

    /**
     * A successful result bound to another session than the pending one.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    abstract protected function resultOfAnotherBinding(): VerificationResult;
}
