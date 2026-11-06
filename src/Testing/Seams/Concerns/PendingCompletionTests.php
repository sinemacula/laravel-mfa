<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingCompletionContract;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * The `PendingCompletion` contract kit: a result of the pending session is
 * accepted; a result bound elsewhere, a failed result, and a result handed by a
 * caller with no pending session are refused by throwing. Each is handed by
 * `pendingCaller()`, the pending session's caller, whose client a completion
 * that judges the client overrides to carry what it needs.
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
     * A successful result of the pending session is accepted.
     *
     * @return void
     */
    public function testPendingCompletionAcceptsAResultOfThePendingSession(): void
    {
        PendingCompletionContract::assertAcceptsAResultOfThePendingSession($this->pendingCompletion(), $this->pendingCaller(), $this->resultOfThePendingSession());
    }

    /**
     * A result bound to another session, identity, application or purpose is
     * refused.
     *
     * @return void
     */
    public function testPendingCompletionRefusesAResultOfAnotherBinding(): void
    {
        PendingCompletionContract::assertRefusesAResultOfAnotherBinding($this->pendingCompletion(), $this->pendingCaller(), $this->resultOfAnotherBinding());
    }

    /**
     * A failed result is refused.
     *
     * @return void
     */
    public function testPendingCompletionRefusesAFailedResult(): void
    {
        PendingCompletionContract::assertRefusesAFailedResult($this->pendingCompletion(), $this->pendingCaller());
    }

    /**
     * A result of the pending session handed by a caller with no pending
     * session is refused.
     *
     * @return void
     */
    public function testPendingCompletionRefusesACallerWithNoPendingSession(): void
    {
        PendingCompletionContract::assertRefusesACallerWithNoPendingSession($this->pendingCompletion(), $this->pendingCaller(), $this->resultOfThePendingSession());
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
     * A successful result bound to the pending session, which the completion
     * would accept from its caller.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    abstract protected function resultOfThePendingSession(): VerificationResult;

    /**
     * A successful result bound to another session than the pending one.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    abstract protected function resultOfAnotherBinding(): VerificationResult;

    /**
     * The pending session's caller, which hands each result: by default with a
     * client of which nothing is known. A completion that judges the client,
     * such as one that checks a cookie-borne request is same-site, overrides it
     * with a client carrying what that check needs.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    protected function pendingCaller(): CallerContext
    {
        return CallerContext::forPending($this->pendingContext());
    }
}
