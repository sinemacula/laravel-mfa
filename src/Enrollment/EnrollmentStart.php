<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * How starting an enrolment ended. The grant, secret and URI are returned only
 * here; send them with `Secrets\SecretResponse::json()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentStart
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $grant
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $secret
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $provisioningUri
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     */
    private function __construct(

        /** Pending factor, when started. */
        public ?FactorSummary $factor = null,

        /** Confirms the factor; shown once. */
        public ?RevealedSecret $grant = null,

        /** Grant expiry; nothing renews it. */
        public ?CarbonImmutable $expiresAt = null,

        /** Factor secret, when its type has one; shown once. */
        public ?RevealedSecret $secret = null,

        /** Authenticator app URI, when its type provisions one; shown once. */
        public ?RevealedSecret $provisioningUri = null,

        /** Refusal reason, when not started. */
        public ?FailureReason $reason = null,

        /** Seconds until a code may be sent, when waiting helps. */
        public ?int $retryAfter = null,

        /** Lockout end, when refused by one that ends at a set time. */
        public ?CarbonImmutable $lockedUntil = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $grant
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $secret
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $provisioningUri
     * @return self
     */
    public static function started(
        FactorSummary $factor,
        #[\SensitiveParameter] RevealedSecret $grant,
        CarbonImmutable $expiresAt,
        #[\SensitiveParameter] ?RevealedSecret $secret = null,
        #[\SensitiveParameter] ?RevealedSecret $provisioningUri = null,
    ): self {
        return new self($factor, $grant, $expiresAt, $secret, $provisioningUri);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return self
     */
    public static function refused(FailureReason $reason, ?int $retryAfter = null, ?CarbonImmutable $lockedUntil = null): self
    {
        return new self(reason: $reason, retryAfter: $retryAfter, lockedUntil: $lockedUntil);
    }

    /**
     * @return bool
     */
    public function hasStarted(): bool
    {
        return $this->reason === null;
    }
}
