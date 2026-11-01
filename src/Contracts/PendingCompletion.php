<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Pending completion contract.
 *
 * Receives a successful verification on a pending session. The implementation
 * validates the result's binding (identity, application, session and purpose),
 * records the proof on the session and evaluates the whole outstanding
 * requirement again: the session activates, stays pending for the rest of the
 * requirement, or moves on to its next step. A result is never handed over as
 * `amr` alone.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PendingCompletion
{
    /**
     * Hand a successful verification to the pending session it was made in.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return void
     */
    public function complete(PendingContext $pending, VerificationResult $result): void;
}
