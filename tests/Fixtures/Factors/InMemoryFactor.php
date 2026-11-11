<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use Tests\Fixtures\Factors\Concerns\ReportsUsableFactorDefaults;

/**
 * A read-only `Factor` that is not an `EloquentFactor`, so the manager skips
 * state changes for it.
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
     * @param  string  $type
     * @param  ?string  $secret
     * @param  ?string  $destination
     * @param  ?string  $label
     * @param  mixed  $identifier
     * @return void
     */
    public function __construct(

        /** @var string */
        private readonly string $type = 'totp',

        /** @var ?string */
        private readonly ?string $secret = null,

        /** @var ?string */
        private readonly ?string $destination = null,

        /** @var ?string */
        private readonly ?string $label = null,

        /** @var mixed */
        private readonly mixed $identifier = 'factor-id',
    ) {}

    /**
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return $this->label;
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return $this->destination;
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return $this->secret;
    }
}
