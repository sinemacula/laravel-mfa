<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Minimal in-memory Factor implementation used by MfaManager tests
 * that need to exercise the non-Eloquent branch of the orchestration
 * pipeline without touching the database.
 *
 * Satisfies only the read-only `Factor` contract; the manager's
 * verification pipeline explicitly skips state mutation when the
 * factor does not implement `EloquentFactor`, which is exactly the
 * branch this fixture is designed to exercise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class InMemoryFactor implements Factor
{
    /**
     * Build an in-memory factor double with the provided immutable
     * state. The optional `$authenticatable` argument lets the fixture
     * report ownership to the manager's cross-account guard — leaving
     * it null mirrors the pre-guard "owner unknown" shape and trips the
     * `FactorOwnershipMismatchException` path.
     *
     * @param  string  $driver
     * @param  ?string  $secret
     * @param  ?string  $code
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @param  int  $attempts
     * @param  ?\Carbon\CarbonInterface  $lockedUntil
     * @param  ?\Carbon\CarbonInterface  $verifiedAt
     * @param  ?string  $recipient
     * @param  ?string  $label
     * @param  mixed  $identifier
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $authenticatable
     * @return void
     */
    public function __construct(
        private readonly string $driver = 'totp',
        private readonly ?string $secret = null,
        private readonly ?string $code = null,
        private readonly ?CarbonInterface $expiresAt = null,
        private int $attempts = 0,
        private readonly ?CarbonInterface $lockedUntil = null,
        private readonly ?CarbonInterface $verifiedAt = null,
        private readonly ?string $recipient = null,
        private readonly ?string $label = null,
        private readonly mixed $identifier = 'factor-id',
        private readonly ?Authenticatable $authenticatable = null,
    ) {}

    /**
     * Return the configured factor identifier verbatim.
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return $this->identifier;
    }

    /**
     * Return the driver name this in-memory factor reports against.
     *
     * @return string
     */
    public function getDriver(): string
    {
        return $this->driver;
    }

    /**
     * Return the optional human-readable label.
     *
     * @return ?string
     */
    public function getLabel(): ?string
    {
        return $this->label;
    }

    /**
     * Return the optional delivery recipient.
     *
     * @return ?string
     */
    public function getRecipient(): ?string
    {
        return $this->recipient;
    }

    /**
     * Return the authenticatable bound at construction time, or `null`
     * when the fixture was built without an owner.
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
     * Report whether the factor is currently locked (i.e. has a
     * future lock expiry).
     *
     * @return bool
     */
    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil->isFuture();
    }

    /**
     * Always returns `null`; the fixture does not track attempt
     * timestamps.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastAttemptedAt(): ?CarbonInterface
    {
        return null;
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
