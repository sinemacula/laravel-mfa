<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Whether a factor's challenge may be sent or checked now.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ChallengeAdmission
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  string  $detail
     */
    private function __construct(

        /** Null when admitted. */
        public ?FailureReason $reason,

        /** Lockout end; null when admitted or held at the failure ceiling. */
        public ?CarbonImmutable $lockedUntil,

        /** For logs only. */
        public string $detail,
    ) {}

    /**
     * @return self
     */
    public static function admit(): self
    {
        return new self(null, null, 'The factor may be challenged.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @return self
     */
    public static function locked(Lockout $lockout): self
    {
        return new self(FailureReason::LOCKED, $lockout->until, $lockout->detail());
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     */
    public static function refuse(FailureReason $reason, string $detail): self
    {
        return new self($reason, null, $detail);
    }

    /**
     * @return bool
     */
    public function isAdmitted(): bool
    {
        return $this->reason === null;
    }
}
