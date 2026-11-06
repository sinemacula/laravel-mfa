<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * What every `PendingCompletion` must guarantee, as assertions: a successful
 * result of the pending session is accepted from its caller; a result whose
 * binding does not validate against the pending session, a failed result, and a
 * result handed by a caller with no pending session are refused by throwing an
 * `OperationRefusedException`, never by returning. Each is handed by the caller
 * given, whose client carries the facts the completion's own checks need, so a
 * refusal is the one the assertion means rather than one of a client it cannot
 * judge.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class PendingCompletionContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A successful result bound to the pending session is accepted from its
     * caller.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $matching
     * @return void
     */
    public static function assertAcceptsAResultOfThePendingSession(PendingCompletion $completion, CallerContext $caller, VerificationResult $matching): void
    {
        self::assertPending($caller);

        try {
            $completion->complete($caller, $matching);
        } catch (\Throwable $exception) {
            Assert::fail(sprintf('A result of the pending session must be accepted, but %s was thrown: %s', $exception::class, $exception->getMessage()));
        }

        Assert::assertTrue(true);
    }

    /**
     * A result bound to another session, identity, application or purpose than
     * the pending session's is refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $mismatched
     * @return void
     */
    public static function assertRefusesAResultOfAnotherBinding(PendingCompletion $completion, CallerContext $caller, VerificationResult $mismatched): void
    {
        self::assertPending($caller);

        SeamAssert::refusesWithAReason(static fn () => $completion->complete($caller, $mismatched), 'A result bound elsewhere must be refused with a reason.');
    }

    /**
     * A failed result is refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertRefusesAFailedResult(PendingCompletion $completion, CallerContext $caller): void
    {
        self::assertPending($caller);

        $failed = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');

        SeamAssert::refusesWithAReason(static fn () => $completion->complete($caller, $failed), 'A failed result must be refused with a reason.');
    }

    /**
     * A result of the pending session handed by the same identity, on the same
     * application and from the same client, but with no pending session, is
     * refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $matching
     * @return void
     */
    public static function assertRefusesACallerWithNoPendingSession(PendingCompletion $completion, CallerContext $caller, VerificationResult $matching): void
    {
        $pending = self::assertPending($caller);
        $active  = CallerContext::forIdentity($pending->identity, $pending->application, $caller->client);

        SeamAssert::refusesWithAReason(static fn () => $completion->complete($active, $matching), 'A caller with no pending session must be refused with a reason.');
    }

    /**
     * The caller's pending session, failing the check when the caller given has
     * none.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private static function assertPending(CallerContext $caller): PendingContext
    {
        $pending = $caller->pending;

        Assert::assertNotNull($pending, 'The caller a pending completion is proved with must be on a pending session.');

        return $pending;
    }
}
