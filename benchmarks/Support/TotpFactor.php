<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Benchmarks\Support\Concerns\ReportsUsableFactorDefaults;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Read-only TOTP factor: with nowhere to record a step the driver accepts no
 * code, but still computes the whole window, which is the cost measured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TotpFactor implements Factor
{
    use ReportsUsableFactorDefaults;

    /**
     * @param  string  $secret
     * @return void
     */
    public function __construct(

        /** Base32 shared secret. */
        #[\SensitiveParameter] private string $secret,
    ) {}

    /**
     * @return string
     */
    #[\Override]
    public function getTotpAlgorithm(): string
    {
        return 'sha1';
    }

    /**
     * @return int
     */
    #[\Override]
    public function getTotpDigits(): int
    {
        return 6;
    }

    /**
     * @return int
     */
    #[\Override]
    public function getTotpPeriod(): int
    {
        return 30;
    }

    /**
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'bench-totp-factor';
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
     * @return string
     */
    #[\Override]
    public function getSecret(): string
    {
        return $this->secret;
    }
}
