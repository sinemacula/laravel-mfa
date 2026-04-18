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
 * Pure-PHP single-use recovery code driver. Each backup code is stored as its
 * own `Factor` row: enrolment mints N rows, successful verification deletes the
 * matching row, replay against a consumed code fails because the row no longer
 * exists.
 *
 * Codes are stored hashed on the `secret` column (encrypted at rest via the
 * shipped model's `encrypted` cast). Verification is constant-time via
 * `hash_equals`. Generation draws each character of the configured alphabet
 * uniformly via `random_int` for cryptographic suitability.
 *
 * No challenge issuance — backup codes are pre-minted at enrolment and the user
 * holds them out-of-band.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class BackupCodeDriver implements FactorDriver
{
    /** @var string Driver identifier used on Factor::driver. */
    public const string NAME = 'backup_code';

    /** @var callable(int, int): int Bound at construction — `random_int(...)` by default. */
    private $randomInt;

    /**
     * Constructor.
     *
     * `$randomInt` is the injectable randomness seam — defaults to PHP's
     * built-in `random_int(...)` (CSPRNG-backed). Tests substitute a
     * deterministic callable to exercise the generator against known outputs
     * without relying on the real RNG.
     *
     * @param  int  $codeLength
     * @param  string  $alphabet
     * @param  int  $codeCount
     * @param  ?callable(int, int): int  $randomInt
     */
    public function __construct(

        /** Length of each minted backup code, in characters. */
        private readonly int $codeLength = 10,

        /** Character set codes are drawn from. */
        private readonly string $alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',

        /** Default number of codes minted per `generateSet()` call. */
        private readonly int $codeCount = 10,

        // Randomness seam — `null` binds to PHP's CSPRNG `random_int`.
        ?callable $randomInt = null,

    ) {
        $this->randomInt = $randomInt ?? random_int(...);
    }

    /**
     * Backup codes have no server-issued challenge — codes are minted at
     * enrolment time and delivered to the user out-of-band (download /
     * copy-paste / print).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    #[\Override]
    public function issueChallenge(Factor $factor): void
    {
        // No-op — backup codes are pre-issued at enrolment.
    }

    /**
     * Verify the submitted code against the factor's stored hash in constant
     * time. On success marks the code consumed by clearing the stored secret —
     * the manager then persists the mutation.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $stored = $factor->getSecret();

        if ($stored === null || $stored === '' || !hash_equals($stored, $this->hash($code))) {
            return false;
        }

        // Single-use consumption: an atomic conditional UPDATE closes the
        // TOCTOU race where two concurrent requests would both match the
        // same code. Only the request whose UPDATE finds the still-
        // unconsumed secret wins; the loser sees zero affected rows and
        // returns false. Non-Eloquent factors have no row to consume, so
        // the comparison alone constitutes the verification result.
        return $factor instanceof EloquentFactor
            ? $this->consumeAtomic($factor, $stored)
            : true;
    }

    /**
     * Backup codes are minted in batches — this single-code entry point returns
     * one freshly generated plaintext code. Enrolment flows typically call
     * `generateSet()` instead to mint the full batch in one go.
     *
     * @return string
     */
    #[\Override]
    public function generateSecret(): string
    {
        return $this->generatePlaintextCode();
    }

    /**
     * Hash a plaintext code for persistence.
     *
     * SHA-256 rather than a password hash because backup codes are already
     * high-entropy random strings; a slow hash adds latency without meaningful
     * extra security against credential-stuffing.
     *
     * @param  string  $code
     * @return string
     */
    public function hash(#[\SensitiveParameter] string $code): string
    {
        return hash('sha256', $code);
    }

    /**
     * Generate a fresh set of plaintext backup codes. Callers must hash via
     * `hash()` before persistence and surface plaintext to the user
     * out-of-band.
     *
     * Optional `$count` overrides the configured default for one call (useful
     * for admin / break-glass batches without rebinding the driver). Must be
     * positive.
     *
     * @param  ?int  $count
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function generateSet(?int $count = null): array
    {
        $effectiveCount = $count ?? $this->codeCount;

        if ($effectiveCount < 1) {
            throw new \InvalidArgumentException(sprintf('Backup-code count must be at least 1; got [%d].', $effectiveCount));
        }

        $codes = [];

        for ($i = 0; $i < $effectiveCount; $i++) {
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
     * Uses a pessimistic row lock inside a short transaction to close the
     * TOCTOU race where two concurrent requests would both match the same hash.
     * The secret column is cast to `encrypted` on the shipped model, so we
     * cannot compare encrypted-at-rest values directly in a WHERE clause —
     * hence the `lockForUpdate()` pattern rather than a conditional UPDATE.
     * Returns `true` when this request consumed the code, `false` when another
     * beat us to it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $expectedSecret
     * @return bool
     */
    private function consumeAtomic(EloquentFactor $factor, #[\SensitiveParameter] string $expectedSecret): bool
    {
        if (!$factor instanceof Model) {
            return true;
        }

        $secretColumn = $factor->getSecretName();

        /** @var bool $result */
        $result = DB::connection($factor->getConnectionName())->transaction(
            static function () use ($factor, $secretColumn, $expectedSecret): bool {
                /** @var ?\Illuminate\Database\Eloquent\Model $locked */
                // @phpstan-ignore staticMethod.dynamicCall
                $locked = $factor->newQuery()
                    ->lockForUpdate()
                    ->find($factor->getKey());

                if (!$locked instanceof EloquentFactor) {
                    return false;
                }

                $currentSecret = $locked->getSecret();

                if (
                    $currentSecret === null
                    || !hash_equals($currentSecret, $expectedSecret)
                ) {
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
     * Generate a single plaintext backup code from the configured alphabet +
     * length, picking characters with `random_int` for cryptographic
     * suitability.
     *
     * @return string
     */
    private function generatePlaintextCode(): string
    {
        $alphabetLength = strlen($this->alphabet);
        $randomInt      = $this->randomInt;
        $code           = '';

        for ($i = 0; $i < $this->codeLength; $i++) {
            $code .= $this->alphabet[$randomInt(0, $alphabetLength - 1)];
        }

        return $code;
    }
}
