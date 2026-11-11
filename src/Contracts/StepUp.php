<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Receives a successful verification on an active session and refreshes its
 * authentication from the proof without starting a new session.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface StepUp
{
    /**
     * Runs as the last write of the factor state transaction; refuse by
     * throwing, never by returning, so the code's use rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function stepUp(CallerContext $caller, VerificationResult $result): ?object;
}
