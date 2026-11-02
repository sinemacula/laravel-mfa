<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How checking a code against a challenge ended, as whoever owns the challenge
 * reports it: passed; failed for the reason, which the owner has counted
 * through `ChallengeCounters::report()`; or refused for the reason before any
 * code was checked, which counted nothing, with when a lockout refusing it
 * ends, if it ends at a set time.
 *
 * The detail is for events and logs only: what the caller is told is the
 * reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ChallengeOutcome
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  bool  $counted
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     */
    private function __construct(

        /** Why the code was not accepted, or `null` when it was. */
        public ?FailureReason $reason,

        /** What happened in detail, for events and logs only. */
        public string $detail,

        /** Whether the outcome was counted against the factor and the identity. */
        public bool $counted,

        /** When the lockout refusing the challenge ends, when it ends at a set time. */
        public ?CarbonImmutable $lockedUntil = null,
    ) {}

    /**
     * The code answered the challenge, which it used up.
     *
     * @return self
     */
    public static function passed(): self
    {
        return new self(null, 'The code answered the challenge.', true);
    }

    /**
     * The code did not answer the challenge, and that was counted.
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
     * No code was checked, and nothing was counted.
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
     * Whether the code answered the challenge.
     *
     * @return bool
     */
    public function hasPassed(): bool
    {
        return $this->reason === null;
    }
}
