<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Benchmarks\Support\Concerns\ReportsUsableFactorDefaults;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Non-persisting TOTP `Factor` for the TOTP driver benchmarks: a secret and the
 * default parameters (SHA-1, 6 digits, 30 seconds), and nothing else.
 *
 * It implements only the `Factor` read surface, so it has nowhere to record an
 * accepted time step and the driver accepts no code for it; every verification
 * still computes and compares the whole window, which is the cost measured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TotpFactor implements Factor
{
    use ReportsUsableFactorDefaults;

    /**
     * Build the factor over a Base32 secret.
     *
     * @param  string  $secret
     * @return void
     */
    public function __construct(

        /** The shared secret, in Base32. */
        #[\SensitiveParameter] private string $secret,
    ) {}

    /**
     * The HMAC algorithm: SHA-1.
     *
     * @return ?string
     */
    #[\Override]
    public function getTotpAlgorithm(): ?string
    {
        return 'sha1';
    }

    /**
     * The number of digits: 6.
     *
     * @return ?int
     */
    #[\Override]
    public function getTotpDigits(): ?int
    {
        return 6;
    }

    /**
     * The period: 30 seconds.
     *
     * @return ?int
     */
    #[\Override]
    public function getTotpPeriod(): ?int
    {
        return 30;
    }

    /**
     * A fixed identifier.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'bench-totp-factor';
    }

    /**
     * The TOTP type.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'totp';
    }

    /**
     * No label.
     *
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return null;
    }

    /**
     * No destination.
     *
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return null;
    }

    /**
     * No owner.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function getAuthenticatable(): ?Authenticatable
    {
        return null;
    }

    /**
     * The shared secret.
     *
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * No delivered code.
     *
     * @return ?string
     */
    #[\Override]
    public function getCode(): ?string
    {
        return null;
    }

    /**
     * No code expiry.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getExpiresAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * No failed attempts.
     *
     * @return int
     */
    #[\Override]
    public function getAttempts(): int
    {
        return 0;
    }

    /**
     * No lockout.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLockedUntil(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Never locked.
     *
     * @return bool
     */
    #[\Override]
    public function isLocked(): bool
    {
        return false;
    }

    /**
     * Never attempted.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastAttemptedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Never verified.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getVerifiedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Never verified.
     *
     * @return bool
     */
    #[\Override]
    public function isVerified(): bool
    {
        return false;
    }
}
