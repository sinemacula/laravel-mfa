<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * How starting an enrolment ended: started, with the pending factor as a
 * summary, the grant that may confirm it and when that ends, and for a TOTP
 * factor its secret and provisioning URI; or refused, with the reason a caller
 * may be told and, when waiting will help, how long to wait.
 *
 * The grant, the secret and the URI are returned here and never again, as
 * secrets for the response: send them with `Secrets\SecretResponse::json()`. A
 * refusal holds none of them, and none can be dumped, encoded or serialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentStart
{
    /**
     * Constructor.
     *
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

        /** The pending factor, when the enrolment started. */
        public ?FactorSummary $factor = null,

        /** The grant that may confirm it, shown once. */
        public ?RevealedSecret $grant = null,

        /** When the grant stops confirming; nothing renews it. */
        public ?CarbonImmutable $expiresAt = null,

        /** The factor's secret, shown once, when its type has one. */
        public ?RevealedSecret $secret = null,

        /** The URI an authenticator app reads the secret from, shown once, when its type provisions one. */
        public ?RevealedSecret $provisioningUri = null,

        /** Why the enrolment did not start, when it did not. */
        public ?FailureReason $reason = null,

        /** The seconds until a code may be sent, when no code could be and waiting will help. */
        public ?int $retryAfter = null,

        /** When the lockout refusing the enrolment ends, when it ends at a set time. */
        public ?CarbonImmutable $lockedUntil = null,
    ) {}

    /**
     * An enrolment that started.
     *
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
     * An enrolment refused for the reason.
     *
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
     * Whether the enrolment started.
     *
     * @return bool
     */
    public function hasStarted(): bool
    {
        return $this->reason === null;
    }
}
