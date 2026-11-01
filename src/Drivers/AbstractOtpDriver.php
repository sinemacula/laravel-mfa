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
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractOtpDriver implements FactorDriver
{
    /** @var \Closure(int, int): int Bound at construction - `random_int(...)` by default. */
    protected \Closure $randomInt;

    /**
     * Constructor.
     *
     * The code length and lifetime are taken as given: the shipped drivers are
     * built from `mfa.codes`, whose bounds the package checks when it boots
     * (see `Codes\CodeSettings`).
     *
     * `$randomInt` is the injectable randomness seam — defaults to PHP's
     * built-in `random_int(...)` (CSPRNG-backed); tests substitute a
     * deterministic callable.
     *
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  ?callable(int, int): int  $randomInt
     */
    public function __construct(

        /** Number of digits in the one-time code minted by `generateCode()`. */
        protected readonly int $codeLength = 6,

        /** Minutes before an issued code is considered expired. */
        protected readonly int $expiry = 10,

        // Randomness seam — `null` binds to PHP's built-in CSPRNG `random_int`.
        ?callable $randomInt = null,
    ) {
        $this->randomInt = $randomInt === null ? random_int(...) : $randomInt(...);
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

        // Dispatch before persist: if the transport throws, nothing is stored
        // against the factor, so the user does not end up with a "valid" code
        // they never received.
        $this->dispatch($factor, $code);

        $factor->issueCode($code, $expiresAt);

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
     * The `amr` value of a code sent to the factor: `otp`.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp'];
    }

    /**
     * Delivered codes keep no persistent secret: each is drawn when it is sent
     * by `issueChallenge()`, so starting an enrolment returns none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return null
     */
    #[\Override]
    public function startEnrollment(Factor $factor): ?string
    {
        return null;
    }

    /**
     * Confirm the pending factor with the code sent to it, checked as any
     * other.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        return $this->verify($factor, $code);
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
     * Generate a numeric, zero-padded one-time code of the configured length,
     * drawn with `random_int` for cryptographic suitability (vs `mt_rand` /
     * `rand`).
     *
     * @return string
     */
    protected function generateCode(): string
    {
        $randomInt = $this->randomInt;

        return str_pad((string) $randomInt(0, (10 ** $this->codeLength) - 1), $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Deliver the issued code to the factor's destination via the subclass's
     * chosen transport.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $code
     * @return void
     */
    abstract protected function dispatch(EloquentFactor $factor, #[\SensitiveParameter] string $code): void;
}
