<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Benchmarks\Support\Concerns\ReportsUsableFactorDefaults;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Non-persisting factor, so driver benchmarks skip Eloquent and the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class InMemoryFactor implements Factor
{
    use ReportsUsableFactorDefaults;

    /**
     * @param  string  $type
     * @param  ?string  $id
     * @param  ?string  $label
     * @param  ?string  $destination
     * @param  ?string  $secret
     * @return void
     */
    public function __construct(

        /** Factor type. */
        private string $type,

        /** Factor identifier. */
        private ?string $id = 'bench-factor',

        /** Label. */
        private ?string $label = null,

        /** Delivery destination for OTP drivers. */
        private ?string $destination = null,

        /** Secret or hash the driver verifies against. */
        #[\SensitiveParameter] private ?string $secret = null,
    ) {}

    /**
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return $this->id;
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
