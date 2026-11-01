<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

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
}
