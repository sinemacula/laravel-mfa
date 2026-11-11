<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Outcome of a code send request. Never holds the code.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SendResult
{
    /**
     * @param  ?string  $challengeId
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** Challenge the code was sent for, when sent. */
        public ?string $challengeId,

        /** Code expiry, when sent. */
        public ?CarbonImmutable $expiresAt,

        /** Refusal reason, when not sent. */
        public ?FailureReason $reason,

        /** Seconds (at least 1) until a retry can succeed, when waiting helps. */
        public ?int $retryAfter,
    ) {}

    /**
     * @param  string  $challengeId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return self
     */
    public static function sent(string $challengeId, CarbonImmutable $expiresAt): self
    {
        return new self($challengeId, $expiresAt, null, null);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function refused(FailureReason $reason, ?int $retryAfter = null): self
    {
        return new self(null, null, $reason, $retryAfter === null ? null : max(1, $retryAfter));
    }

    /**
     * Refusal from an admission; a lockout sets the retry to its end.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission  $admission
     * @return self
     */
    public static function refusedBy(ChallengeAdmission $admission): self
    {
        $until = $admission->lockedUntil;

        return self::refused($admission->reason ?? FailureReason::NOT_FOUND, $until === null ? null : $until->getTimestamp() - CarbonImmutable::now()->getTimestamp());
    }

    /**
     * @return bool
     */
    public function wasSent(): bool
    {
        return $this->reason === null;
    }
}
