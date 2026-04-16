<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * Machine-readable reason codes for MFA verification failures.
 *
 * Surfaced on the `MfaVerificationFailed` event so downstream consumers
 * (audit log sinks, SIEM integrations, support tooling) can attribute
 * failures without parsing human-readable messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
enum MfaVerificationFailureReason: string
{
    /**
     * Factor is currently locked due to too many failed attempts.
     */
    case FactorLocked = 'factor_locked';

    /**
     * The submitted code did not match the stored / expected value.
     */
    case CodeInvalid = 'code_invalid';

    /**
     * The pending one-time code expired before verification.
     */
    case CodeExpired = 'code_expired';

    /**
     * No pending code was issued for an OTP driver that requires one.
     */
    case CodeMissing = 'code_missing';

    /**
     * A TOTP factor has no persistent secret stored.
     */
    case SecretMissing = 'secret_missing';

    /**
     * The named driver is not registered with the MFA manager.
     */
    case DriverUnknown = 'driver_unknown';

    /**
     * The currently authenticated identity is not MFA-capable.
     */
    case IdentityUnsupported = 'identity_unsupported';
}
