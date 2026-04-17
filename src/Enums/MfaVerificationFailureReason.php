<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * Machine-readable reason codes for MFA verification failures.
 *
 * Surfaced on the `MfaVerificationFailed` event so downstream consumers (audit
 * log sinks, SIEM integrations, support tooling) can attribute failures without
 * parsing human-readable messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
enum MfaVerificationFailureReason: string
{
    /**
     * Factor is currently locked due to too many failed attempts.
     */
    case FACTOR_LOCKED = 'factor_locked';

    /**
     * The submitted code did not match the stored / expected value.
     */
    case CODE_INVALID = 'code_invalid';

    /**
     * The pending one-time code expired before verification.
     */
    case CODE_EXPIRED = 'code_expired';

    /**
     * No pending code was issued for an OTP driver that requires one.
     */
    case CODE_MISSING = 'code_missing';

    /**
     * A TOTP factor has no persistent secret stored.
     */
    case SECRET_MISSING = 'secret_missing';
}
