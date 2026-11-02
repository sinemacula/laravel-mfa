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
     * It runs as the last write of the identity's factor state transaction, on
     * the storage connection, after the code is spent and counted. Returning
     * means the proof was accepted, including when the session stays pending
     * for the rest of its requirement; what it returns is opaque to this
     * package and reaches the caller as `VerificationResult::$completion`. A
     * result whose binding does not validate, or a proof that cannot be
     * recorded, is refused by throwing an `OperationRefusedException` carrying
     * the reason, never by returning, so the code's use and the count roll back
     * with it. Any other throwable propagates to the caller.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function complete(PendingContext $pending, VerificationResult $result): ?object;
}
