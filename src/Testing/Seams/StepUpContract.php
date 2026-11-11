<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * What every `StepUp` must guarantee: a failed result, or one not bound to the
 * active session, throws an `OperationRefusedException`, never returns.
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
     * Another session, identity, application or purpose than the active one's.
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
