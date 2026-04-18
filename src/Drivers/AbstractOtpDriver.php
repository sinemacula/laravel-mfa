<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\Carbon;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;

/**
 * Base class for one-time-code delivery drivers (email, SMS).
 *
 * Collapses the shared code-generation + persistence + constant-time
 * verification logic so concrete drivers only need to describe their transport
 * — sending the code via Laravel's mail subsystem, an SMS gateway, a push
 * notification channel, etc.
 *
 * Persistence is required: OTP challenges are meaningless without a stored code
 * to compare against. Subclasses therefore operate on
 * `EloquentFactor`-implementing factors only; passing a non-persistable factor
 * raises `UnsupportedFactorException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
abstract class AbstractOtpDriver implements FactorDriver
{
    /** @var callable(int, int): int Bound at construction — `random_int(...)` by default. */
    protected $randomInt;

    /**
     * Constructor.
     *
     * `$codeLength`, `$expiry`, and `$maxAttempts` are validated at construction
     * time so deployment-time misconfigurations surface in the stack trace
     * rather than as a broken user flow. `$codeLength` and `$expiry` must be at
     * least 1; `$maxAttempts` must be non-negative (0 is the documented
     * "lockout disabled" value).
     *
     * `$alphabet` controls the `generateCode()` character set: `null` keeps
     * numeric zero-padded codes; a non-null string picks uniformly from it.
     * Empty / single-character alphabets are rejected so misconfigurations
     * fail fast.
     *
     * `$randomInt` is the injectable randomness seam — defaults to PHP's
     * built-in `random_int(...)` (CSPRNG-backed); tests substitute a
     * deterministic callable.
     *
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     * @param  ?string  $alphabet
     * @param  ?callable(int, int): int  $randomInt
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    public function __construct(

        /** Length of the one-time code minted by `generateCode()`. */
        protected readonly int $codeLength = 6,

        /** Minutes before an issued code is considered expired. */
        protected readonly int $expiry = 10,

        /** Per-factor attempt ceiling before the manager applies a lockout. */
        protected readonly int $maxAttempts = 3,

        /** Optional character set for `generateCode()`; `null` uses numeric zero-padded codes. */
        protected readonly ?string $alphabet = null,

        // Randomness seam — `null` binds to PHP's built-in CSPRNG `random_int`.
        ?callable $randomInt = null,

    ) {
        $this->assertValidCodeLength($codeLength);
        $this->assertValidExpiry($expiry);
        $this->assertValidMaxAttempts($maxAttempts);
        $this->assertValidAlphabet($alphabet);

        $this->randomInt = $randomInt ?? random_int(...);
    }

    /**
     * Issue a fresh one-time code against the factor and dispatch it through
     * the subclass transport.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    #[\Override]
    public function issueChallenge(Factor $factor): void
    {
        if (!$factor instanceof EloquentFactor) {
            throw new UnsupportedFactorException('OTP drivers require a persistable EloquentFactor; got ' . get_debug_type($factor) . '.');
        }

        $code      = $this->generateCode();
        $expiresAt = Carbon::now()->addMinutes($this->expiry);

        // Dispatch before persist: if the transport throws, nothing is
        // stored against the factor, so the user does not end up with a
        // "valid" code they never received.
        $this->dispatch($factor, $code);

        $factor->issueCode($code, $expiresAt);

        // Pair the attempt-state reset with a freshly minted code: the
        // OTP family rotates its secret on every challenge, so clearing
        // a prior lockout cannot be used as a free unlock — the attacker
        // has to receive the new code through the configured transport
        // before they can verify against it. Drivers that do NOT rotate
        // a secret per challenge (TOTP, backup codes) deliberately
        // preserve their lockout state across `challenge()` calls.
        $factor->resetAttempts();

        $factor->persist();
    }

    /**
     * Verify the submitted code against the factor's pending code in constant
     * time.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    #[\Override]
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
     * OTP drivers do not use persistent secrets; their secret material is the
     * per-challenge code, generated on demand by `issueChallenge()`.
     *
     * @return null
     */
    #[\Override]
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

    /**
     * Get the configured code alphabet, or null when codes are drawn from the
     * default numeric set.
     *
     * @return ?string
     */
    public function getAlphabet(): ?string
    {
        return $this->alphabet;
    }

    /**
     * Deliver the issued code to the factor's recipient via the subclass's
     * chosen transport.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $code
     * @return void
     */
    abstract protected function dispatch(EloquentFactor $factor, #[\SensitiveParameter] string $code): void;

    /**
     * Generate a one-time code of the configured length. Uses `random_int` for
     * cryptographic suitability (vs `mt_rand` / `rand`).
     *
     * Defaults to a numeric, zero-padded code so the historical contract holds
     * when no alphabet is configured. When an alphabet is supplied, each
     * character is drawn uniformly from it via `random_int`.
     *
     * @return string
     */
    protected function generateCode(): string
    {
        $randomInt = $this->randomInt;

        if ($this->alphabet === null) {
            return str_pad(
                (string) $randomInt(0, (10 ** $this->codeLength) - 1),
                $this->codeLength,
                '0',
                STR_PAD_LEFT,
            );
        }

        $alphabetLength = strlen($this->alphabet);
        $code           = '';

        for ($i = 0; $i < $this->codeLength; $i++) {
            $code .= $this->alphabet[$randomInt(0, $alphabetLength - 1)];
        }

        return $code;
    }

    /**
     * Reject code lengths below 1 — the numeric path would otherwise mint a
     * one-character `"0"` code and the alphabet path an empty string.
     *
     * @param  int  $codeLength
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    private function assertValidCodeLength(int $codeLength): void
    {
        if ($codeLength < 1) {
            throw InvalidDriverConfigurationException::codeLengthTooSmall('OTP code length', $codeLength);
        }
    }

    /**
     * Reject expiry windows below 1 minute — any issued code would otherwise
     * be "expired" on arrival.
     *
     * @param  int  $expiry
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    private function assertValidExpiry(int $expiry): void
    {
        if ($expiry < 1) {
            throw InvalidDriverConfigurationException::expiryTooSmall('OTP expiry', $expiry);
        }
    }

    /**
     * Reject negative `maxAttempts` — the manager's `>=` lockout threshold
     * would never match, silently disabling the lockout.
     *
     * @param  int  $maxAttempts
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    private function assertValidMaxAttempts(int $maxAttempts): void
    {
        if ($maxAttempts < 0) {
            throw InvalidDriverConfigurationException::negativeMaxAttempts('OTP max attempts', $maxAttempts);
        }
    }

    /**
     * Reject alphabets with fewer than two characters — a single-character
     * alphabet mints zero-entropy codes; an empty alphabet explodes inside
     * `random_int(0, -1)`. `null` is the documented "use the default numeric
     * set" signal and bypasses the check.
     *
     * @param  ?string  $alphabet
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    private function assertValidAlphabet(?string $alphabet): void
    {
        if ($alphabet !== null && strlen($alphabet) < 2) {
            throw InvalidDriverConfigurationException::alphabetTooShort('OTP alphabet', $alphabet);
        }
    }
}
