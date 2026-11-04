<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * How confirming an enrolment ended: confirmed, with the factor, the recovery
 * codes generated with an identity's first factor and, on a pending session,
 * the verification the new proof made there or, on an active one, what the
 * bound `SessionTransition` returned for the caller; or failed, with the reason
 * a caller may be told, when a lockout refusing it ends, and whether the
 * failure used up the enrolment's attempts and abandoned it.
 *
 * The recovery codes are returned here and never again, as secrets for the
 * response; a failure holds none. The completion may hold a credential, so it
 * is held as a `\SensitiveParameterValue` and read through `completion()`, and
 * no dump shows it. Answered once: a second confirmation with the same grant is
 * `not_found`, and returns none of this again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentConfirmation
{
    /** @var \SensitiveParameterValue What the session transition returned, hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $recoveryCodes
     * @param  ?\SineMacula\Laravel\Mfa\Verification\VerificationResult  $verification
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  bool  $abandoned
     * @param  ?object  $completion
     */
    private function __construct(

        /** The factor, when it was confirmed. */
        public ?FactorSummary $factor = null,

        /** The recovery codes generated with it: none unless it is the first and the level allows. */
        public array $recoveryCodes = [],

        /** What the new proof made of a pending session; none on an active one. */
        public ?VerificationResult $verification = null,

        /** Why the factor was not confirmed, when it was not. */
        public ?FailureReason $reason = null,

        /** When the lockout refusing the confirmation ends, when it ends at a set time. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Whether the failure abandoned the enrolment, so it must start again. */
        public bool $abandoned = false,

        // What the session transition returned on an active session, opaque to
        // this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * A factor that was confirmed.
     *
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
     * A confirmation that failed for the reason.
     *
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
     * What the bound session transition returned for the caller on an active
     * session, such as a pending session's new credential, or `null`; on a
     * pending session the verification's `completion()` is the one.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }

    /**
     * Whether the factor was confirmed.
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->reason === null;
    }
}
