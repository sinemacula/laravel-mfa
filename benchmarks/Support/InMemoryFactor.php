<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Benchmarks\Support\Concerns\ReportsUsableFactorDefaults;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Non-persisting `Factor` implementation used for benchmarks.
 *
 * Skips Eloquent / database overhead so the benchmarks measure the driver
 * verification logic in isolation. Mutable properties so benchmarks can reset a
 * factor's code, expiry, or secret between iterations without reconstructing
 * the entire object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InMemoryFactor implements Factor
{
    use ReportsUsableFactorDefaults;

    /**
     * Build a benchmark factor double with the supplied mutable state.
     *
     * @param  string  $type
     * @param  ?string  $id
     * @param  ?string  $label
     * @param  ?string  $destination
     * @param  ?string  $secret
     * @param  ?string  $code
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @param  int  $attempts
     * @param  ?\Carbon\CarbonInterface  $lockedUntil
     * @param  ?\Carbon\CarbonInterface  $lastAttemptedAt
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $authenticatable
     * @return void
     */
    public function __construct(

        /** The factor type (e.g. `'totp'`, `'backup_code'`). */
        private string $type,

        /** Factor identifier returned by `getFactorIdentifier()`. */
        private ?string $id = 'bench-factor',

        /** Optional human-readable label. */
        private ?string $label = null,

        /** Delivery destination for OTP drivers; null otherwise. */
        private ?string $destination = null,

        /** Stored secret / hash material the driver verifies against. */
        #[\SensitiveParameter] private ?string $secret = null,

        /** Pending one-time code awaiting verification. */
        private ?string $code = null,

        /** Expiry timestamp of the pending code. */
        private ?CarbonInterface $expiresAt = null,

        /** Consecutive failed verification attempts. */
        private int $attempts = 0,

        /** Lockout expiry after too many failed attempts. */
        private ?CarbonInterface $lockedUntil = null,

        /** Timestamp of the most recent verification attempt. */
        private ?CarbonInterface $lastAttemptedAt = null,

        /** Owning authenticatable, if bound. */
        private ?Authenticatable $authenticatable = null,
    ) {}

    /**
     * Replace the stored secret material between benchmark iterations.
     *
     * @param  ?string  $secret
     * @return void
     */
    public function setSecret(#[\SensitiveParameter] ?string $secret): void
    {
        $this->secret = $secret;
    }

    /**
     * Seed the pending one-time code and its expiry between iterations.
     *
     * @param  ?string  $code
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    public function seedCode(#[\SensitiveParameter] ?string $code, ?CarbonInterface $expiresAt): void
    {
        $this->code      = $code;
        $this->expiresAt = $expiresAt;
    }

    /**
     * Return the configured factor identifier.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return the configured type.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Return the configured label.
     *
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return $this->label;
    }

    /**
     * Return the configured delivery destination.
     *
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return $this->destination;
    }

    /**
     * Return the configured authenticatable, if any.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function getAuthenticatable(): ?Authenticatable
    {
        return $this->authenticatable;
    }

    /**
     * Return the configured secret value.
     *
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * Return the configured one-time code value.
     *
     * @return ?string
     */
    #[\Override]
    public function getCode(): ?string
    {
        return $this->code;
    }

    /**
     * Return the configured code expiry.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getExpiresAt(): ?CarbonInterface
    {
        return $this->expiresAt;
    }

    /**
     * Return the configured attempt count.
     *
     * @return int
     */
    #[\Override]
    public function getAttempts(): int
    {
        return $this->attempts;
    }

    /**
     * Return the configured lock expiry.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLockedUntil(): ?CarbonInterface
    {
        return $this->lockedUntil;
    }

    /**
     * Report whether the factor is currently locked.
     *
     * @return bool
     */
    #[\Override]
    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil->isFuture();
    }

    /**
     * Return the configured last-attempted timestamp.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastAttemptedAt(): ?CarbonInterface
    {
        return $this->lastAttemptedAt;
    }
}
