<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * How confirming an enrolment ended. Answered once: recovery codes are returned
 * only here, and a second confirmation with the same grant is `not_found`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentConfirmation
{
    /** @var \SensitiveParameterValue May hold a credential. */
    private \SensitiveParameterValue $completion;

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $recoveryCodes
     * @param  ?\SineMacula\Laravel\Mfa\Verification\VerificationResult  $verification
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  bool  $abandoned
     * @param  ?object  $completion
     */
    private function __construct(

        /** Factor, when confirmed. */
        public ?FactorSummary $factor = null,

        /** Only for an identity's first factor, when the level allows. */
        public array $recoveryCodes = [],

        /** Pending session only. */
        public ?VerificationResult $verification = null,

        /** Failure reason, when not confirmed. */
        public ?FailureReason $reason = null,

        /** Lockout end, when refused by one that ends at a set time. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Whether the failure used up the attempts, so it must start again. */
        public bool $abandoned = false,

        // Opaque session transition result, on an active session.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $recoveryCodes
     * @param  ?\SineMacula\Laravel\Mfa\Verification\VerificationResult  $verification
     * @param  ?object  $completion
     * @return self
     */
    public static function confirmed(
        FactorSummary $factor,
        #[\SensitiveParameter] array $recoveryCodes = [],
        #[\SensitiveParameter] ?VerificationResult $verification = null,
        #[\SensitiveParameter] ?object $completion = null,
    ): self {
        return new self($factor, $recoveryCodes, $verification, completion: $completion);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  bool  $abandoned
     * @return self
     */
    public static function failed(FailureReason $reason, ?CarbonImmutable $lockedUntil = null, bool $abandoned = false): self
    {
        return new self(reason: $reason, lockedUntil: $lockedUntil, abandoned: $abandoned);
    }

    /**
     * The `SessionTransition` result on an active session; on a pending one use
     * the verification's `completion()`.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }

    /**
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->reason === null;
    }
}
