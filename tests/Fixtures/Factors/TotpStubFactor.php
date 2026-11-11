<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

/**
 * An in-memory TOTP factor that records a time step only when it is later than
 * the last one, as the shipped model does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TotpStubFactor extends AbstractEloquentFactorStub
{
    /** @var ?int */
    private ?int $lastAcceptedStep = null;

    /**
     * @param  ?string  $secret
     * @param  ?string  $algorithm
     * @param  ?int  $digits
     * @param  ?int  $period
     * @return void
     */
    public function __construct(

        /** Base32. */
        #[\SensitiveParameter]
        private readonly ?string $secret,

        /** @var ?string */
        private readonly ?string $algorithm = 'sha1',

        /** @var ?int */
        private readonly ?int $digits = 6,

        /** In seconds. */
        private readonly ?int $period = 30,
    ) {}

    /**
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'totp-stub';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'totp';
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * @return ?string
     */
    #[\Override]
    public function getTotpAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    /**
     * @return ?int
     */
    #[\Override]
    public function getTotpDigits(): ?int
    {
        return $this->digits;
    }

    /**
     * @return ?int
     */
    #[\Override]
    public function getTotpPeriod(): ?int
    {
        return $this->period;
    }

    /**
     * @return ?int
     */
    #[\Override]
    public function getLastAcceptedStep(): ?int
    {
        return $this->lastAcceptedStep;
    }

    /**
     * @param  int  $step
     * @return bool
     */
    #[\Override]
    public function storeAcceptedStep(int $step): bool
    {
        if ($this->lastAcceptedStep !== null && $this->lastAcceptedStep >= $step) {
            return false;
        }

        $this->lastAcceptedStep = $step;

        return true;
    }
}
