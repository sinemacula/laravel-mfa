<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * What every `StepUp` must guarantee, as assertions: a result whose binding
 * does not validate against the active session, and a failed result, are
 * refused by throwing an `OperationRefusedException`, never by returning.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class StepUpContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A result bound to another session, identity, application or purpose than
     * the active session's is refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\StepUp  $stepUp
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $mismatched
     * @return void
     */
    public static function assertRefusesAResultOfAnotherBinding(StepUp $stepUp, CallerContext $caller, VerificationResult $mismatched): void
    {
        SeamAssert::refusesWithAReason(static fn () => $stepUp->stepUp($caller, $mismatched), 'A result bound elsewhere must be refused with a reason.');
    }

    /**
     * A failed result is refused by throwing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\StepUp  $stepUp
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertRefusesAFailedResult(StepUp $stepUp, CallerContext $caller): void
    {
        $failed = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');

        SeamAssert::refusesWithAReason(static fn () => $stepUp->stepUp($caller, $failed), 'A failed result must be refused with a reason.');
    }
}
