<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How one route's check of a submission ended, under the identity's lock:
 * passed, with what it observed, the challenge it answered and, for a recovery
 * code, how many remain; failed and counted; or refused and counted nowhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckOutcome
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  bool  $counted
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  ?string  $challengeId
     * @param  ?int  $remaining
     */
    private function __construct(

        /** Why the check did not pass, or `null` when it did. */
        public ?FailureReason $reason,

        /** What happened in detail, for events and logs only. */
        public string $detail,

        /** Whether the check was counted as an attempt. */
        public bool $counted,

        /** When the lockout refusing the check lifts, if it lifts by itself. */
        public ?CarbonImmutable $lockedUntil = null,

        /** What the check observed, when it passed. */
        public ?ObservedProperties $properties = null,

        /** The challenge a passed check answered, when one was used. */
        public ?string $challengeId = null,

        /** How many recovery codes a passed redemption left unused. */
        public ?int $remaining = null,
    ) {}

    /**
     * A check that passed.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  ?string  $challengeId
     * @param  ?int  $remaining
     * @return self
     */
    public static function passed(ObservedProperties $properties, ?string $challengeId = null, ?int $remaining = null): self
    {
        return new self(null, 'The submission was accepted.', true, null, $properties, $challengeId, $remaining);
    }

    /**
     * A check that failed, and was counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     */
    public static function failed(FailureReason $reason, string $detail): self
    {
        return new self($reason, $detail, true);
    }

    /**
     * A check refused before anything was counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return self
     */
    public static function refused(FailureReason $reason, string $detail, ?CarbonImmutable $lockedUntil = null): self
    {
        return new self($reason, $detail, false, $lockedUntil);
    }

    /**
     * A check an admission refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission  $admission
     * @return self
     */
    public static function refusedBy(ChallengeAdmission $admission): self
    {
        return new self($admission->reason ?? FailureReason::LOCKED, $admission->detail, false, $admission->lockedUntil);
    }

    /**
     * Whether the check passed.
     *
     * @return bool
     */
    public function hasPassed(): bool
    {
        return $this->reason === null;
    }
}
