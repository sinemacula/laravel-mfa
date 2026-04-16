<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;

/**
 * Email factor driver.
 *
 * Verifies one-time codes delivered via email. The driver checks
 * the submitted code against the stored code on the factor,
 * enforcing expiry. Attempt counting and lockout orchestration are
 * handled by the MFA manager.
 *
 * Challenge issuance (code generation + mail dispatch) is wired up
 * in a later phase; for now `issueChallenge()` is a stub.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class EmailDriver implements FactorDriver
{
    /**
     * Create a new email driver instance.
     *
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     */
    public function __construct(
        private readonly int $codeLength = 6,
        private readonly int $expiry = 10,
        private readonly int $maxAttempts = 3,
    ) {}

    /**
     * Issue a fresh one-time code against the factor and dispatch
     * it via Laravel's mail subsystem.
     *
     * Wired up in Phase 3 (B-09). Currently a no-op so the contract
     * can be satisfied while the manager orchestration lands.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void
    {
        // Stub — code generation and Mailable dispatch land with the manager
        // challenge orchestration.
    }

    /**
     * Verify the submitted code against the factor's pending code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $stored  = $factor->getCode();
        $expires = $factor->getExpiresAt();

        if ($stored === null || $expires === null) {
            return false;
        }

        if ($expires->isPast()) {
            return false;
        }

        return hash_equals($stored, $code);
    }

    /**
     * Email codes are generated on demand; no persistent secret is
     * required.
     *
     * @return null
     */
    public function generateSecret(): ?string
    {
        return null;
    }

    /**
     * Get the configured code length.
     *
     * @return int
     */
    public function getCodeLength(): int
    {
        return $this->codeLength;
    }

    /**
     * Get the configured expiry in minutes.
     *
     * @return int
     */
    public function getExpiry(): int
    {
        return $this->expiry;
    }

    /**
     * Get the configured maximum attempts.
     *
     * @return int
     */
    public function getMaxAttempts(): int
    {
        return $this->maxAttempts;
    }
}
