<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Receives a successful verification on a pending session, records the proof
 * and evaluates the whole outstanding requirement again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PendingCompletion
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
    public function complete(CallerContext $caller, VerificationResult $result): ?object;
}
