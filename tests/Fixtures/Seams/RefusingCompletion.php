<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Throws the given refusal for every result, as an adapter whose authentication
 * layer refuses or fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusingCompletion implements PendingCompletion, StepUp
{
    /**
     * @param  \Throwable  $refusal
     */
    public function __construct(

        /** Thrown for every result. */
        private \Throwable $refusal,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \Throwable
     */
    #[\Override]
    public function complete(CallerContext $caller, VerificationResult $result): ?object
    {
        throw $this->refusal;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \Throwable
     */
    #[\Override]
    public function stepUp(CallerContext $caller, VerificationResult $result): ?object
    {
        throw $this->refusal;
    }
}
