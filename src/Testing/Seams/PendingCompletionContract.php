<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * What every `PendingCompletion` must guarantee, as assertions: a result whose
 * binding does not validate against the pending session, and a failed result,
 * are refused by throwing, never by returning.
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
     * A result bound to another session, identity, application or purpose than
     * the pending session's is refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $mismatched
     * @return void
     */
    public static function assertRefusesAResultOfAnotherBinding(PendingCompletion $completion, PendingContext $pending, VerificationResult $mismatched): void
    {
        SeamAssert::refusesByThrowing(static fn () => $completion->complete($pending, $mismatched), 'A result bound elsewhere must be refused by throwing.');
    }

    /**
     * A failed result is refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return void
     */
    public static function assertRefusesAFailedResult(PendingCompletion $completion, PendingContext $pending): void
    {
        $failed = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');

        SeamAssert::refusesByThrowing(static fn () => $completion->complete($pending, $failed), 'A failed result must be refused by throwing.');
    }
}
