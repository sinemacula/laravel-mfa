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
 * factor's secret between iterations without reconstructing the entire object.
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
     * @param  ?\Carbon\CarbonInterface  $verifiedAt
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

        /** Timestamp of the most recent successful verification. */
        private ?CarbonInterface $verifiedAt = null,

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
     * Return the configured verification timestamp.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getVerifiedAt(): ?CarbonInterface
    {
        return $this->verifiedAt;
    }

    /**
     * Report whether the factor has been verified at least once.
     *
     * @return bool
     */
    #[\Override]
    public function isVerified(): bool
    {
        return $this->verifiedAt !== null;
    }
}
