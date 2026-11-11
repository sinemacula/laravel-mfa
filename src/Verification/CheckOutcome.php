<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How one route's check of a submission ended under the identity's lock:
 * passed, failed and counted, or refused and counted nowhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckOutcome
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  bool  $counted
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  ?string  $challengeId
     * @param  ?int  $remaining
     */
    private function __construct(

        /** `null` when the check passed. */
        public ?FailureReason $reason,

        /** For events and logs only. */
        public string $detail,

        /** Whether the check counted as an attempt. */
        public bool $counted,

        /** When the refusing lockout lifts, if it lifts by itself. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Set when the check passed. */
        public ?ObservedProperties $properties = null,

        /** The challenge answered, when it passed or a seam refused after one was reported. */
        public ?string $challengeId = null,

        /** Recovery codes left unused by a passed redemption. */
        public ?int $remaining = null,
    ) {}

    /**
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
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     */
    public static function failed(FailureReason $reason, string $detail): self
    {
        return new self($reason, $detail, true);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?string  $challengeId
     * @return self
     */
    public static function refused(FailureReason $reason, string $detail, ?CarbonImmutable $lockedUntil = null, ?string $challengeId = null): self
    {
        return new self($reason, $detail, false, $lockedUntil, null, $challengeId);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission  $admission
     * @return self
     */
    public static function refusedBy(ChallengeAdmission $admission): self
    {
        return new self($admission->reason ?? FailureReason::LOCKED, $admission->detail, false, $admission->lockedUntil);
    }

    /**
     * @return bool
     */
    public function hasPassed(): bool
    {
        return $this->reason === null;
    }
}
