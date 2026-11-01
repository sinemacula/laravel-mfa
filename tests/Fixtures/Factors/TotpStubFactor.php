<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

/**
 * TOTP factor fixture holding its secret, parameters and last accepted time
 * step in memory: it records a step as the shipped model does, only when it is
 * later than the last one, so the driver's single-use rule can be exercised
 * without a database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TotpStubFactor extends AbstractEloquentFactorStub
{
    /** @var ?int The last time step a code was accepted for. */
    private ?int $lastAcceptedStep = null;

    /**
     * Capture the secret and parameters.
     *
     * @param  ?string  $secret
     * @param  ?string  $algorithm
     * @param  ?int  $digits
     * @param  ?int  $period
     * @return void
     */
    public function __construct(

        /** Stored TOTP shared secret, in Base32. */
        #[\SensitiveParameter]
        private readonly ?string $secret,

        /** The HMAC algorithm the factor was enrolled with. */
        private readonly ?string $algorithm = 'sha1',

        /** The number of digits in the factor's codes. */
        private readonly ?int $digits = 6,

        /** The period of the factor's time steps, in seconds. */
        private readonly ?int $period = 30,
    ) {}

    /**
     * Return the fixture's fixed factor identifier.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'totp-stub';
    }

    /**
     * Return the TOTP driver name.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'totp';
    }

    /**
     * Return the seeded TOTP secret.
     *
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * Return the seeded HMAC algorithm.
     *
     * @return ?string
     */
    #[\Override]
    public function getTotpAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    /**
     * Return the seeded number of digits.
     *
     * @return ?int
     */
    #[\Override]
    public function getTotpDigits(): ?int
    {
        return $this->digits;
    }

    /**
     * Return the seeded period.
     *
     * @return ?int
     */
    #[\Override]
    public function getTotpPeriod(): ?int
    {
        return $this->period;
    }

    /**
     * Return the last time step a code was accepted for.
     *
     * @return ?int
     */
    #[\Override]
    public function getLastAcceptedStep(): ?int
    {
        return $this->lastAcceptedStep;
    }

    /**
     * Record the step when it is later than the last one accepted.
     *
     * @param  int  $step
     * @return bool
     */
    #[\Override]
    public function acceptStep(int $step): bool
    {
        if ($this->lastAcceptedStep !== null && $this->lastAcceptedStep >= $step) {
            return false;
        }

        $this->lastAcceptedStep = $step;

        return true;
    }
}
