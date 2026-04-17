<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\Carbon;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;

/**
 * Base class for one-time-code delivery drivers (email, SMS).
 *
 * Collapses the shared code-generation + persistence + constant-time
 * verification logic so concrete drivers only need to describe their
 * transport — sending the code via Laravel's mail subsystem, an SMS
 * gateway, a push notification channel, etc.
 *
 * Persistence is required: OTP challenges are meaningless without a
 * stored code to compare against. Subclasses therefore operate on
 * `EloquentFactor`-implementing factors only; passing a non-persistable
 * factor raises `UnsupportedFactorException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
abstract class AbstractOtpDriver implements FactorDriver
{
    /**
     * Constructor.
     *
     * `$alphabet` controls the per-character set used by `generateCode()`:
     * `null` (default) preserves the historical numeric behaviour;
     * a non-null string switches to picking characters uniformly from
     * the supplied alphabet. Empty and single-character alphabets are
     * rejected at construction so misconfigurations fail fast rather
     * than at first code issuance.
     *
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     * @param  ?string  $alphabet
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        protected readonly int $codeLength = 6,
        protected readonly int $expiry = 10,
        protected readonly int $maxAttempts = 3,
        protected readonly ?string $alphabet = null,
    ) {
        if ($alphabet !== null && strlen($alphabet) < 2) {
            $detail = $alphabet === '' ? 'an empty string' : 'a single character';

            throw new \InvalidArgumentException('OTP alphabet must contain at least two characters; received ' . $detail . '.');
        }
    }

    /**
     * Issue a fresh one-time code against the factor and dispatch it
     * through the subclass transport.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
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
     * Verify the submitted code against the factor's pending code in
     * constant time.
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
     * OTP drivers do not use persistent secrets; their secret material is
     * the per-challenge code, generated on demand by `issueChallenge()`.
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

    /**
     * Get the configured code alphabet, or null when codes are drawn
     * from the default numeric set.
     *
     * @return ?string
     */
    public function getAlphabet(): ?string
    {
        return $this->alphabet;
    }

    /**
     * Deliver the issued code to the factor's recipient via the
     * subclass's chosen transport.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $code
     * @return void
     */
    abstract protected function dispatch(
        EloquentFactor $factor,
        #[\SensitiveParameter]
        string $code,
    ): void;

    /**
     * Generate a one-time code of the configured length. Uses `random_int`
     * for cryptographic suitability (vs `mt_rand` / `rand`).
     *
     * Defaults to a numeric, zero-padded code so the historical contract
     * holds when no alphabet is configured. When an alphabet is supplied,
     * each character is drawn uniformly from it via `random_int`.
     *
     * @return string
     */
    protected function generateCode(): string
    {
        if ($this->alphabet === null) {
            return str_pad(
                (string) random_int(0, (10 ** $this->codeLength) - 1),
                $this->codeLength,
                '0',
                STR_PAD_LEFT,
            );
        }

        $alphabetLength = strlen($this->alphabet);
        $code           = '';

        for ($i = 0; $i < $this->codeLength; $i++) {
            $code .= $this->alphabet[random_int(0, $alphabetLength - 1)];
        }

        return $code;
    }
}
