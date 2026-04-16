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
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     */
    public function __construct(
        protected readonly int $codeLength = 6,
        protected readonly int $expiry = 10,
        protected readonly int $maxAttempts = 3,
    ) {}

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

        $factor->issueCode($code, $expiresAt);
        $factor->persist();

        $this->dispatch($factor, $code);
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
     * Generate a numeric one-time code of the configured length. Uses
     * `random_int` for cryptographic suitability (vs `mt_rand` / `rand`).
     *
     * @return string
     */
    protected function generateCode(): string
    {
        $min = 0;
        $max = (10 ** $this->codeLength) - 1;

        return str_pad(
            (string) random_int($min, $max),
            $this->codeLength,
            '0',
            STR_PAD_LEFT,
        );
    }
}
