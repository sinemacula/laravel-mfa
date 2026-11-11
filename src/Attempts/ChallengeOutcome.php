<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How a challenge check ended, as reported by the challenge's owner. A refusal
 * means no code was checked and nothing was counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ChallengeOutcome
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  bool  $counted
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     */
    private function __construct(

        /** Null when passed; the only part the caller is told. */
        public ?FailureReason $reason,

        /** For events and logs only. */
        public string $detail,

        /** Whether the factor and identity counters recorded it. */
        public bool $counted,

        /** Lockout end, when refused by one that ends at a set time. */
        public ?CarbonImmutable $lockedUntil = null,
    ) {}

    /**
     * @return self
     */
    public static function passed(): self
    {
        return new self(null, 'The code answered the challenge.', true);
    }

    /**
     * The owner has counted the failure through `ChallengeCounters::report()`.
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
     * @return bool
     */
    public function hasPassed(): bool
    {
        return $this->reason === null;
    }
}
