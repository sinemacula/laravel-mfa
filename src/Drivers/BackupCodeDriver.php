<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
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

        // Single-use consumption: an atomic conditional UPDATE closes the
        // TOCTOU race where two concurrent requests could both match the
        // same code. Only the request whose UPDATE finds the still-
        // unconsumed secret wins; the loser sees zero affected rows and
        // returns false.
        if ($factor instanceof EloquentFactor) {
            return $this->consumeAtomic($factor, $stored);
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
     * Atomically consume the factor's stored secret.
     *
     * Uses a pessimistic row lock inside a short transaction to close
     * the TOCTOU race where two concurrent requests would both match
     * the same hash. The secret column is cast to `encrypted` on the
     * shipped model, so we cannot compare encrypted-at-rest values
     * directly in a WHERE clause — hence the `lockForUpdate()` pattern
     * rather than a conditional UPDATE. Returns `true` when this
     * request consumed the code, `false` when another beat us to it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $expectedSecret
     * @return bool
     */
    private function consumeAtomic(
        EloquentFactor $factor,
        #[\SensitiveParameter]
        string $expectedSecret,
    ): bool {
        if (!$factor instanceof Model) {
            return true;
        }

        $secretColumn = $factor->getSecretName();

        /** @var bool $result */
        $result = DB::connection($factor->getConnectionName())->transaction(
            static function () use ($factor, $secretColumn, $expectedSecret): bool {
                /** @var ?EloquentFactor $locked */
                $locked = $factor->newQuery()
                    ->lockForUpdate()
                    ->find($factor->getKey());

                if ($locked === null) {
                    return false;
                }

                $currentSecret = $locked->getSecret();

                if ($currentSecret === null
                    || !hash_equals($currentSecret, $expectedSecret)
                ) {
                    return false;
                }

                if (!$locked instanceof Model) {
                    return false;
                }

                $locked->setAttribute($secretColumn, null);
                $locked->save();

                return true;
            },
        );

        if ($result) {
            $factor->setAttribute($secretColumn, null);
        }

        return $result;
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
