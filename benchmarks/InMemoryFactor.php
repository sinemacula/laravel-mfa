<?php

declare(strict_types = 1);

namespace Benchmarks;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Non-persisting `Factor` implementation used for benchmarks.
 *
 * Skips Eloquent / database overhead so the benchmarks measure the
 * driver verification logic in isolation. Mutable properties so
 * benchmarks can reset a factor's code, expiry, or secret between
 * iterations without reconstructing the entire object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class InMemoryFactor implements Factor
{
    /**
     * Constructor.
     *
     * @param  string  $driver
     * @param  ?string  $id
     * @param  ?string  $label
     * @param  ?string  $recipient
     * @param  ?string  $secret
     * @param  ?string  $code
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @param  int  $attempts
     * @param  ?\Carbon\CarbonInterface  $lockedUntil
     * @param  ?\Carbon\CarbonInterface  $lastAttemptedAt
     * @param  ?\Carbon\CarbonInterface  $verifiedAt
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $authenticatable
     */
    public function __construct(
        public string $driver,
        public ?string $id = 'bench-factor',
        public ?string $label = null,
        public ?string $recipient = null,
        public ?string $secret = null,
        public ?string $code = null,
        public ?CarbonInterface $expiresAt = null,
        public int $attempts = 0,
        public ?CarbonInterface $lockedUntil = null,
        public ?CarbonInterface $lastAttemptedAt = null,
        public ?CarbonInterface $verifiedAt = null,
        public ?Authenticatable $authenticatable = null,
    ) {}

    public function getFactorIdentifier(): mixed
    {
        return $this->id;
    }

    public function getDriver(): string
    {
        return $this->driver;
    }

    public function getLabel(): ?string
    {
        return $this->label;
    }

    public function getRecipient(): ?string
    {
        return $this->recipient;
    }

    public function getAuthenticatable(): ?Authenticatable
    {
        return $this->authenticatable;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function getCode(): ?string
    {
        return $this->code;
    }

    public function getExpiresAt(): ?CarbonInterface
    {
        return $this->expiresAt;
    }

    public function getAttempts(): int
    {
        return $this->attempts;
    }

    public function getLockedUntil(): ?CarbonInterface
    {
        return $this->lockedUntil;
    }

    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil->isFuture();
    }

    public function getLastAttemptedAt(): ?CarbonInterface
    {
        return $this->lastAttemptedAt;
    }

    public function getVerifiedAt(): ?CarbonInterface
    {
        return $this->verifiedAt;
    }

    public function isVerified(): bool
    {
        return $this->verifiedAt !== null;
    }
}
