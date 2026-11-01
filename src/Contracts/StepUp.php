<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

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
     * Returning means the proof was accepted and recorded. A result whose
     * binding does not validate, or a proof that cannot be recorded, is refused
     * by throwing, never by returning, so the change the call is part of rolls
     * back.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return void
     *
     * @throws \RuntimeException
     */
    public function stepUp(VerificationResult $result): void;
}
