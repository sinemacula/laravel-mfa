<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * How a verification ended: verified, with the proof it made and the evaluation
 * of the session's proofs with it, or failed, with the reason a caller may be
 * told and the detail that stays internal. A lockout also carries the time it
 * lifts.
 *
 * A failure is a result rather than an exception, so the caller answers it as
 * it chooses; exceptions are kept for misconfiguration and server errors. The
 * detail is for events and logs only: an answer to the person carries the
 * reason, within the disclosure boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerificationResult
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     */
    private function __construct(

        /** The proof the verification made, when it succeeded. */
        public ?Proof $proof = null,

        /** The evaluation of the session's proofs with the new one, when it succeeded. */
        public ?Evaluation $evaluation = null,

        /** Why the verification failed, when it did. */
        public ?FailureReason $reason = null,

        /** What happened in detail, for events and logs only, when it failed. */
        public ?string $detail = null,

        /** When the lockout lifts, for `locked` only. */
        public ?CarbonImmutable $lockedUntil = null,
    ) {}

    /**
     * A verification that made a proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return self
     */
    public static function verified(Proof $proof, Evaluation $evaluation): self
    {
        return new self(proof: $proof, evaluation: $evaluation);
    }

    /**
     * A verification that failed, with its internal detail and, for a lockout,
     * the time it lifts.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function failed(FailureReason $reason, string $detail, ?CarbonImmutable $lockedUntil = null): self
    {
        if (trim($detail) === '') {
            throw new \InvalidArgumentException('The detail of a failed verification must not be blank.');
        }

        if ($reason === FailureReason::LOCKED && $lockedUntil === null) {
            throw new \InvalidArgumentException('A failure of reason [locked] carries the time the lockout lifts.');
        }

        if ($reason !== FailureReason::LOCKED && $lockedUntil !== null) {
            throw new \InvalidArgumentException(sprintf('Only a failure of reason [locked] carries the time a lockout lifts, not [%s].', $reason->value));
        }

        return new self(reason: $reason, detail: $detail, lockedUntil: $lockedUntil);
    }

    /**
     * Whether the verification made a proof.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->proof !== null;
    }

    /**
     * Whether the verification failed.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->reason !== null;
    }
}
