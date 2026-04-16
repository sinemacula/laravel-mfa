<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;

/**
 * Backup code factor driver.
 *
 * Pure-PHP single-use recovery code driver. Each backup code is stored
 * as its own `Factor` row: enrolment mints N rows, successful
 * verification deletes the matching row, replay against a consumed code
 * fails because the row no longer exists.
 *
 * Codes are stored hashed on the `secret` column (encrypted at rest via
 * the shipped model's `encrypted` cast). Verification is constant-time
 * via `hash_equals`. Generation uses `random_bytes` for cryptographic
 * suitability.
 *
 * No challenge issuance — backup codes are pre-minted at enrolment and
 * the user holds them out-of-band.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class BackupCodeDriver implements FactorDriver
{
    /** @var string Driver identifier used on Factor::driver. */
    public const string NAME = 'backup_code';

    /**
     * Constructor.
     *
     * @param  int  $codeLength
     * @param  string  $alphabet
     * @param  int  $codeCount
     */
    public function __construct(
        private readonly int $codeLength = 10,
        private readonly string $alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',
        private readonly int $codeCount = 10,
    ) {}

    /**
     * Backup codes have no server-issued challenge — codes are minted at
     * enrolment time and delivered to the user out-of-band (download /
     * copy-paste / print).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void
    {
        // No-op — backup codes are pre-issued at enrolment.
    }

    /**
     * Verify the submitted code against the factor's stored hash in
     * constant time. On success marks the code consumed by clearing the
     * stored secret — the manager then persists the mutation.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(
        Factor $factor,
        #[\SensitiveParameter]
        string $code,
    ): bool {
        $stored = $factor->getSecret();

        if ($stored === null || $stored === '') {
            return false;
        }

        $submitted = $this->hash($code);

        if (!hash_equals($stored, $submitted)) {
            return false;
        }

        // Single-use: invalidate the stored code on success. The manager's
        // `EloquentFactor` persistence call will flush this to storage.
        if ($factor instanceof EloquentFactor) {
            $this->consume($factor);
        }

        return true;
    }

    /**
     * Backup codes are minted in batches — this single-code entry point
     * returns one freshly generated plaintext code. Enrolment flows
     * typically call `generateSet()` instead to mint the full batch in
     * one go.
     *
     * @return string
     */
    public function generateSecret(): ?string
    {
        return $this->generatePlaintextCode();
    }

    /**
     * Hash a plaintext code for persistence.
     *
     * SHA-256 rather than a password hash because backup codes are
     * already high-entropy random strings; a slow hash adds latency
     * without meaningful extra security against credential-stuffing.
     *
     * @param  string  $code
     * @return string
     */
    public function hash(#[\SensitiveParameter] string $code): string
    {
        return hash('sha256', $code);
    }

    /**
     * Generate a fresh set of plaintext backup codes. Callers are
     * responsible for hashing via `hash()` before persistence and
     * surfacing the plaintext set to the user out-of-band.
     *
     * @return list<string>
     */
    public function generateSet(): array
    {
        $codes = [];

        for ($i = 0; $i < $this->codeCount; $i++) {
            $codes[] = $this->generatePlaintextCode();
        }

        return $codes;
    }

    /**
     * Get the configured backup-code length.
     *
     * @return int
     */
    public function getCodeLength(): int
    {
        return $this->codeLength;
    }

    /**
     * Get the configured backup-code alphabet.
     *
     * @return string
     */
    public function getAlphabet(): string
    {
        return $this->alphabet;
    }

    /**
     * Get the configured number of codes minted per enrolment.
     *
     * @return int
     */
    public function getCodeCount(): int
    {
        return $this->codeCount;
    }

    /**
     * Mark the factor's stored secret consumed after a successful match.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     */
    private function consume(EloquentFactor $factor): void
    {
        // We reuse `consumeCode()` on the factor which clears code +
        // expires_at. Backup codes store their material on `secret`,
        // so we also null the secret here so the row is effectively
        // spent but still observable in audit trails.
        $factor->issueCode('', $factor->getExpiresAt() ?? \Carbon\Carbon::now());

        // Clear the secret column via setAttribute on the underlying
        // Eloquent model. Because EloquentFactor doesn't expose a
        // setSecret() helper, use the column-name hook.
        if (method_exists($factor, 'setAttribute')) {
            $factor->setAttribute($factor->getSecretName(), null);
            $factor->consumeCode();
        }
    }

    /**
     * Generate a single plaintext backup code from the configured
     * alphabet + length, picking characters with `random_int` for
     * cryptographic suitability.
     *
     * @return string
     */
    private function generatePlaintextCode(): string
    {
        $alphabetLength = strlen($this->alphabet);
        $code           = '';

        for ($i = 0; $i < $this->codeLength; $i++) {
            $code .= $this->alphabet[random_int(0, $alphabetLength - 1)];
        }

        return $code;
    }
}
