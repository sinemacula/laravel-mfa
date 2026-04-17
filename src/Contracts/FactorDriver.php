<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Factor driver contract.
 *
 * Defines the interface for MFA factor drivers. Each driver encapsulates the
 * challenge-issuing and verification logic for a specific type of multi-factor
 * authentication (e.g. TOTP, email, SMS, backup codes).
 *
 * The MFA manager orchestrates attempt counting, lockout state, and event
 * dispatch around every `verify()` / `issueChallenge()` call; drivers remain
 * focused on per-factor-type logic.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface FactorDriver
{
    /**
     * Issue a challenge for the given factor.
     *
     * For drivers that deliver one-time codes (email, SMS) this generates the
     * code, persists it against the factor, and dispatches the outbound
     * message. For drivers whose challenge is implicit (TOTP, where the
     * authenticator app generates codes locally) this is a no-op. For drivers
     * with pre-issued challenges (backup codes) this is also a no-op.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void;

    /**
     * Verify the given code against the factor.
     *
     * Drivers own the per-factor-type comparison (TOTP via Google2FA, OTP via
     * constant-time compare, backup codes consuming the matched single-use
     * code).
     *
     * Drivers MUST NOT mutate attempt counters, lockout state, or verification
     * timestamps — those belong to the manager's orchestration layer. Drivers
     * MAY mutate single-use factor material on success when single-use
     * semantics are intrinsic to the driver (e.g. backup codes marking the
     * consumed code spent).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool;

    /**
     * Generate the seed material the driver uses for fresh enrolment.
     *
     * Per-driver semantics:
     *
     * - TOTP returns the shared base32 secret to persist on
     *   `Factor::$secret` and render into the provisioning URI.
     * - BackupCode returns a single fresh plaintext code; consumers
     *   calling `BackupCodeDriver::generateSet()` get the full batch
     *   in one go.
     * - Email and SMS return `null` — both mint a fresh code per
     *   challenge inside `issueChallenge()`, so there is no
     *   enrolment-time secret to surface.
     *
     * @return ?string
     */
    public function generateSecret(): ?string;
}
