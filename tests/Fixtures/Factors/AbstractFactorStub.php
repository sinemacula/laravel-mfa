<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use Tests\Fixtures\Factors\Concerns\ReportsUsableFactorDefaults;

/**
 * Default implementation of the `Factor` contract for test stubs.
 *
 * Provides safe nulls / zero-default values for every accessor so a test
 * fixture only has to override the methods relevant to the scenario it
 * exercises. Subclasses are typically declared as anonymous classes inside test
 * helpers — extending this base keeps each anonymous class well below the
 * project's max-methods-per-class threshold without resorting to
 * `@SuppressWarnings` annotations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class AbstractFactorStub implements Factor
{
    use ReportsUsableFactorDefaults;

    /**
     * Return the stub's fixed factor identifier.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'stub';
    }

    /**
     * Return the stub's default driver name.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'email';
    }

    /**
     * Return the stub's default label (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return null;
    }

    /**
     * Return the stub's default destination (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return null;
    }

    /**
     * Return the stub's default owning identity (none).
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function getAuthenticatable(): ?Authenticatable
    {
        return null;
    }

    /**
     * Return the stub's default secret (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return null;
    }

    /**
     * Return the stub's default pending code (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getCode(): ?string
    {
        return null;
    }

    /**
     * Return the stub's default code expiry (none).
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getExpiresAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return the stub's default attempt count (zero).
     *
     * @return int
     */
    #[\Override]
    public function getAttempts(): int
    {
        return 0;
    }

    /**
     * Report whether the stub is currently locked.
     *
     * @return bool
     */
    #[\Override]
    public function isLocked(): bool
    {
        // Derived from the accessor so subclasses can flip the lock state by
        // overriding `getLockedUntil()` alone — and so the body is not
        // byte-identical to `isVerified()` (radarlint S4144 flags structurally
        // identical method bodies).
        return $this->getLockedUntil() !== null;
    }

    /**
     * Return the stub's default lockout expiry (none).
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLockedUntil(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return the stub's default last-attempted timestamp (none).
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastAttemptedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Report whether the stub has been verified at least once.
     *
     * @return bool
     */
    #[\Override]
    public function isVerified(): bool
    {
        return $this->getVerifiedAt() !== null;
    }

    /**
     * Return the stub's default verification timestamp (none).
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getVerifiedAt(): ?CarbonInterface
    {
        return null;
    }
}
