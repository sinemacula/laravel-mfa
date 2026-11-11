<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use Tests\Fixtures\Factors\Concerns\ReportsUsableFactorDefaults;

/**
 * Defaults for every `Factor` accessor, so a stub overrides only what its test
 * needs and stays under the methods-per-class limit.
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
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'stub';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'email';
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return null;
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return null;
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return null;
    }
}
