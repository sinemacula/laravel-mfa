<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * A pending completion and step-up that answer every result by throwing what
 * they are given, as an adapter over an authentication layer refuses or fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusingCompletion implements PendingCompletion, StepUp
{
    /**
     * Constructor.
     *
     * @param  \Throwable  $refusal
     */
    public function __construct(

        /** What every result is answered with. */
        private \Throwable $refusal,
    ) {}

    /**
     * Refuse the result.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \Throwable
     */
    #[\Override]
    public function complete(PendingContext $pending, VerificationResult $result): ?object
    {
        throw $this->refusal;
    }

    /**
     * Refuse the result.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \Throwable
     */
    #[\Override]
    public function stepUp(VerificationResult $result): ?object
    {
        throw $this->refusal;
    }
}
