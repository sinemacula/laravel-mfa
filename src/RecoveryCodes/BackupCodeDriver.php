<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Backup code factor driver.
 *
 * Pure-PHP single-use recovery code driver. Each backup code is stored as its
 * own `Factor` row: enrolment mints N rows; successful verification marks the
 * matching row spent by nulling its `secret` column, and replay against a
 * consumed code fails because the nulled secret can no longer hash-match.
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
 * @copyright   2026 Sine Macula Limited
 */
final class BackupCodeDriver implements FactorDriver
{
    /** @var string Driver identifier used on Factor::driver. */
    public const string NAME = 'backup_code';

    /** @var \Closure(int, int): int Bound at construction - `random_int(...)` by default. */
    private \Closure $randomInt;

    /**
     * Constructor.
     *
     * The length, alphabet and count are taken as given: the shipped driver is
     * built from `mfa.recovery_codes`, whose bounds and least entropy the
     * package checks when it boots (see `RecoveryCodes\RecoveryCodeSettings`).
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
        private readonly int $codeLength = 12,

        /** Character set codes are drawn from. */
        private readonly string $alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',

        /** Default number of codes minted per `generateSet()` call. */
        private readonly int $codeCount = 10,

        // Randomness seam — `null` binds to PHP's CSPRNG `random_int`.
        ?callable $randomInt = null,
    ) {
        $this->randomInt = $randomInt === null ? random_int(...) : $randomInt(...);
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
     *
     * @throws \Throwable
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $stored = $factor->getSecret();

        if ($stored === null || $stored === '' || !hash_equals($stored, $this->hash($code))) {
            return false;
        }

        // Single-use consumption: an atomic conditional UPDATE closes the
        // TOCTOU race where two concurrent requests would both match the same
        // code. Only the request whose UPDATE finds the still- unconsumed
        // secret wins; the loser sees zero affected rows and returns false.
        // Non-Eloquent factors have no row to consume, so the comparison alone
        // constitutes the verification result.
        return $factor instanceof EloquentFactor
            ? $this->consumeAtomic($factor, $stored)
            : true;
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
     * Backup codes travel on no channel of their own: they are a fallback, not
     * a factor of the combination policy.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::UNKNOWN;
    }

    /**
     * The `amr` value of a backup code: `otp`.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp'];
    }

    /**
     * Backup codes are minted in batches — this single-code entry point returns
     * one freshly generated plaintext code. Enrolment flows typically call
     * `generateSet()` instead to mint the full batch in one go.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return string
     */
    #[\Override]
    public function startEnrollment(Factor $factor): string
    {
        return $this->generatePlaintextCode();
    }

    /**
     * Confirm with a code of the set, consumed as any other.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        return $this->verify($factor, $code);
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
     * The returned batch is guaranteed distinct: a duplicate draw is re-rolled
     * rather than returned, so consumers receive exactly `$effectiveCount`
     * unique recovery codes. Configurations whose code space is smaller than
     * the requested batch size (`alphabet^codeLength < count`) are rejected —
     * the package cannot mint a distinct batch from a code space that small.
     *
     * @param  ?int  $count
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function generateSet(?int $count = null): array
    {
        $effectiveCount = $count ?? $this->codeCount;

        $this->assertValidBatchCount($effectiveCount);
        $this->assertCodeSpaceAccommodates($effectiveCount);

        $codes = [];

        while (count($codes) < $effectiveCount) {
            $candidate = $this->generatePlaintextCode();

            // Deduplicate against the running batch so callers never receive
            // two identical codes (which would persist as two rows sharing a
            // credential, masquerading as separate recovery codes). The outer
            // code-space check guarantees this loop terminates.
            if (in_array($candidate, $codes, true)) {
                continue;
            }

            $codes[] = $candidate;
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
     * Runs in the owner's factor state transaction (see
     * `Support\FactorStateTransaction`), on the storage connection, so the
     * TOCTOU race where two concurrent requests would both match the same hash
     * is closed by the owner's lock, and a consumption racing a rotation or a
     * removal waits for it. The secret column is cast to `encrypted` on the
     * shipped model, so we cannot compare encrypted-at-rest values directly in
     * a WHERE clause; the row is compared again as stored under the lock
     * instead. Returns `true` when this request consumed the code, `false` when
     * another beat us to it or the row is gone.
     *
     * @imperative
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $expectedSecret
     * @return bool
     *
     * @throws \Throwable
     */
    private function consumeAtomic(EloquentFactor $factor, #[\SensitiveParameter] string $expectedSecret): bool
    {
        if (!$factor instanceof Model) {
            return true;
        }

        $secretColumn = $factor->getSecretName();

        $result = FactorStateTransaction::forFactor(
            $factor,
            static function (Collection $factors) use ($factor, $secretColumn, $expectedSecret): bool {

                $locked = $factors->first(static fn (Model $candidate): bool => $candidate->is($factor));

                if ($locked === null) {
                    return false;
                }

                $currentSecret = $locked->getSecret();

                if ($currentSecret === null || !hash_equals($currentSecret, $expectedSecret)) {
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

    /**
     * Reject batch counts below 1 — the driver cannot mint a sensible zero- or
     * negative-sized batch.
     *
     * @param  int  $count
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertValidBatchCount(int $count): void
    {
        if ($count < 1) {
            throw new \InvalidArgumentException(sprintf('Backup-code count must be at least 1; got [%d].', $count));
        }
    }

    /**
     * Guard against requesting more distinct codes than the configured code
     * space can provide. `alphabet^codeLength` overflows PHP's int range for
     * realistic configurations so the comparison is done with GMP-free integer
     * exponentiation short-circuited once the running product matches or
     * exceeds the requested count.
     *
     * @param  int  $count
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertCodeSpaceAccommodates(int $count): void
    {
        $alphabetLength = strlen($this->alphabet);
        $capacity       = 1;

        for ($i = 0; $i < $this->codeLength; $i++) {
            $capacity *= $alphabetLength;

            if ($capacity >= $count) {
                return;
            }
        }

        $detail = sprintf('alphabet=%d, length=%d, capacity=%d', $alphabetLength, $this->codeLength, $capacity);

        throw new \InvalidArgumentException(sprintf('Backup-code code space (%s) is smaller than the batch size %d.', $detail, $count));
    }
}
