<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use Tests\Fixtures\Factors\Concerns\ReportsUsableFactorDefaults;

/**
 * Minimal in-memory Factor implementation used by MfaManager tests that need to
 * exercise the non-Eloquent branch of the orchestration pipeline without
 * touching the database.
 *
 * Satisfies only the read-only `Factor` contract; the manager's verification
 * pipeline explicitly skips state mutation when the factor does not implement
 * `EloquentFactor`, which is exactly the branch this fixture is designed to
 * exercise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InMemoryFactor implements Factor
{
    use ReportsUsableFactorDefaults;

    /**
     * Build an in-memory factor double with the provided immutable state. The
     * optional `$authenticatable` argument lets the fixture report its owner.
     *
     * @param  string  $type
     * @param  ?string  $secret
     * @param  ?string  $destination
     * @param  ?string  $label
     * @param  mixed  $identifier
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $authenticatable
     * @return void
     */
    public function __construct(

        /** Type reported by the factor. */
        private readonly string $type = 'totp',

        /** Stored secret value. */
        private readonly ?string $secret = null,

        /** Delivery destination (email address, phone number, etc). */
        private readonly ?string $destination = null,

        /** Human-readable factor label. */
        private readonly ?string $label = null,

        /** Factor identifier returned by `getFactorIdentifier()`. */
        private readonly mixed $identifier = 'factor-id',

        /** Owning authenticatable, or `null` for the unowned shape. */
        private readonly ?Authenticatable $authenticatable = null,
    ) {}

    /**
     * Return the configured factor identifier verbatim.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return $this->identifier;
    }

    /**
     * Return the type this in-memory factor reports.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Return the optional human-readable label.
     *
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return $this->label;
    }

    /**
     * Return the optional delivery destination.
     *
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return $this->destination;
    }

    /**
     * Return the authenticatable bound at construction time, or `null` when the
     * fixture was built without an owner.
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
}
