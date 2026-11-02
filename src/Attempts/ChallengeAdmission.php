<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Whether a challenge for a factor may be sent or checked now: admitted;
 * locked, with when the lockout ends (none for a factor or an identity at the
 * failure ceiling); or refused with the reason a caller may be told, and why in
 * detail for logs only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ChallengeAdmission
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  string  $detail
     */
    private function __construct(

        /** Why the challenge may not go ahead, or `null` when it may. */
        public ?FailureReason $reason,

        /** When the lockout refusing it ends, when it ends at a set time. */
        public ?CarbonImmutable $lockedUntil,

        /** What was found in detail, for logs only. */
        public string $detail,
    ) {}

    /**
     * The challenge may go ahead.
     *
     * @return self
     */
    public static function admit(): self
    {
        return new self(null, null, 'The factor may be challenged.');
    }

    /**
     * The challenge is refused by the lockout.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @return self
     */
    public static function locked(Lockout $lockout): self
    {
        return new self(FailureReason::LOCKED, $lockout->until, $lockout->detail());
    }

    /**
     * The challenge is refused for the reason.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     */
    public static function refuse(FailureReason $reason, string $detail): self
    {
        return new self($reason, null, $detail);
    }

    /**
     * Whether the challenge may go ahead.
     *
     * @return bool
     */
    public function isAdmitted(): bool
    {
        return $this->reason === null;
    }
}
