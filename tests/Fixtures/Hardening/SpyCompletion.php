<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Notes each call, then records the proof as the default does so the flow goes
 * on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SpyCompletion implements PendingCompletion, StepUp
{
    /**
     * @param  \Tests\Fixtures\Hardening\LockOrderRecorder  $recorder
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion  $default
     */
    public function __construct(

        /** The log the calls go to. */
        private LockOrderRecorder $recorder,

        /** Records the proof. */
        private ProofStoreCompletion $default,
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
        $this->recorder->seam('complete');

        return $this->default->complete($caller, $result);
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
        $this->recorder->seam('stepUp');

        return $this->default->stepUp($caller, $result);
    }
}
