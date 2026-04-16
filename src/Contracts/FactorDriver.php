<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Factor driver contract.
 *
 * Defines the interface for MFA factor drivers. Each driver
 * encapsulates the challenge-issuing and verification logic for a
 * specific type of multi-factor authentication (e.g. TOTP, email,
 * SMS, backup codes).
 *
 * The MFA manager orchestrates attempt counting, lockout state,
 * and event dispatch around every `verify()` / `issueChallenge()`
 * call; drivers remain focused on per-factor-type logic.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface FactorDriver
{
    /**
     * Issue a challenge for the given factor.
     *
     * For drivers that deliver one-time codes (email, SMS) this
     * generates the code, persists it against the factor, and
     * dispatches the outbound message. For drivers whose challenge
     * is implicit (TOTP, where the authenticator app generates
     * codes locally) this is a no-op. For drivers with pre-issued
     * challenges (backup codes) this is also a no-op.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void;

    /**
     * Verify the given code against the factor.
     *
     * Drivers are responsible for the per-factor-type comparison logic
     * (TOTP uses Google2FA, email / SMS use constant-time comparison of the
     * pending code, backup codes consume a single-use code and mark it
     * consumed on success).
     *
     * Drivers MUST NOT mutate attempt counters, lockout state, or
     * verification timestamps — those side effects belong to the MFA
     * manager's orchestration layer. Drivers MAY mutate single-use factor
     * material on successful verification (e.g. backup codes marking the
     * consumed code spent) when single-use semantics are intrinsic to the
     * driver contract.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool;

    /**
     * Generate a new persistent secret for drivers that use one
     * (TOTP). Returns `null` for drivers whose challenges are
     * issued on demand (email, SMS, backup codes).
     *
     * @return ?string
     */
    public function generateSecret(): ?string;
}
