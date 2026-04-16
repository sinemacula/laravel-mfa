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
    ) {}

    public function getFactorIdentifier(): mixed
    {
        return $this->identifier;
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
        return null;
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
        return null;
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
