<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * The outcome of asking for a code to be sent for a factor: sent, with the
 * challenge's id and when the code stops working, or refused, with the reason
 * and, when waiting will help, the seconds until another may be sent. It never
 * holds the code.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SendResult
{
    /**
     * Constructor.
     *
     * @param  ?string  $challengeId
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** The challenge the code was sent for, when one was sent. */
        public ?string $challengeId,

        /** When the code sent stops working, when one was sent. */
        public ?CarbonImmutable $expiresAt,

        /** Why no code was sent, when none was. */
        public ?FailureReason $reason,

        /** The seconds, at least 1, until another code may be sent, when waiting will help. */
        public ?int $retryAfter,
    ) {}

    /**
     * A code was sent for the challenge.
     *
     * @param  string  $challengeId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return self
     */
    public static function sent(string $challengeId, CarbonImmutable $expiresAt): self
    {
        return new self($challengeId, $expiresAt, null, null);
    }

    /**
     * No code was sent, for the reason, and another may be in the seconds given
     * when waiting will help.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function refused(FailureReason $reason, ?int $retryAfter = null): self
    {
        return new self(null, null, $reason, $retryAfter === null ? null : max(1, $retryAfter));
    }

    /**
     * No code was sent because the challenge may not go ahead, for the reason
     * it gives; when a lockout refuses it, another may be sent once that ends.
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
     * Whether a code was sent.
     *
     * @return bool
     */
    public function wasSent(): bool
    {
        return $this->reason === null;
    }
}
