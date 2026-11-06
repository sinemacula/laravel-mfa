<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Step-up contract.
 *
 * Receives a successful verification on an active session: the implementation
 * validates the result's binding, records the proof on the session it is bound
 * to, and refreshes the session's authentication from it without starting a new
 * session. A result is never handed over as `amr` alone.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface StepUp
{
    /**
     * Hand a successful verification to the active session it was made in.
     *
     * It runs as the last write of the identity's factor state transaction, on
     * the storage connection, after the code is spent and counted. Returning
     * means the proof was accepted; what it returns is opaque to this package
     * and reaches the caller as `VerificationResult::$completion`. A result
     * whose binding does not validate, or a proof that cannot be recorded, is
     * refused by throwing an `OperationRefusedException` carrying the reason,
     * never by returning, so the code's use and the count roll back with it.
     * Any other throwable propagates to the caller.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function stepUp(CallerContext $caller, VerificationResult $result): ?object;
}
