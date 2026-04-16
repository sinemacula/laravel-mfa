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
     * Build a benchmark factor double with the supplied mutable state.
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
     * @return void
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

    /**
     * Return the configured factor identifier.
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return the configured driver name.
     *
     * @return string
     */
    public function getDriver(): string
    {
        return $this->driver;
    }

    /**
     * Return the configured label.
     *
     * @return ?string
     */
    public function getLabel(): ?string
    {
        return $this->label;
    }

    /**
     * Return the configured delivery recipient.
     *
     * @return ?string
     */
    public function getRecipient(): ?string
    {
        return $this->recipient;
    }

    /**
     * Return the configured authenticatable, if any.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    public function getAuthenticatable(): ?Authenticatable
    {
        return $this->authenticatable;
    }

    /**
     * Return the configured secret value.
     *
     * @return ?string
     */
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * Return the configured one-time code value.
     *
     * @return ?string
     */
    public function getCode(): ?string
    {
        return $this->code;
    }

    /**
     * Return the configured code expiry.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getExpiresAt(): ?CarbonInterface
    {
        return $this->expiresAt;
    }

    /**
     * Return the configured attempt count.
     *
     * @return int
     */
    public function getAttempts(): int
    {
        return $this->attempts;
    }

    /**
     * Return the configured lock expiry.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLockedUntil(): ?CarbonInterface
    {
        return $this->lockedUntil;
    }

    /**
     * Report whether the factor is currently locked.
     *
     * @return bool
     */
    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil->isFuture();
    }

    /**
     * Return the configured last-attempted timestamp.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastAttemptedAt(): ?CarbonInterface
    {
        return $this->lastAttemptedAt;
    }

    /**
     * Return the configured verification timestamp.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getVerifiedAt(): ?CarbonInterface
    {
        return $this->verifiedAt;
    }

    /**
     * Report whether the factor has been verified at least once.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->verifiedAt !== null;
    }
}
