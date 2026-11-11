<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors\Concerns;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * The `Factor` accessors a test double rarely varies, answering as a confirmed
 * factor no one has used yet.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReportsUsableFactorDefaults
{
    /**
     * @return ?string
     */
    public function getCredentialReference(): ?string
    {
        return null;
    }

    /**
     * @return ?string
     */
    public function getTotpAlgorithm(): ?string
    {
        return null;
    }

    /**
     * @return ?int
     */
    public function getTotpDigits(): ?int
    {
        return null;
    }

    /**
     * @return ?int
     */
    public function getTotpPeriod(): ?int
    {
        return null;
    }

    /**
     * @return ?int
     */
    public function getLastAcceptedStep(): ?int
    {
        return null;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     */
    public function getStatus(): FactorStatus
    {
        return FactorStatus::CONFIRMED;
    }

    /**
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->getStatus() === FactorStatus::CONFIRMED;
    }

    /**
     * @return bool
     */
    public function isPreferred(): bool
    {
        return false;
    }

    /**
     * @return int
     */
    public function getConsecutiveFailures(): int
    {
        return 0;
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    public function getDisabledAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * @return ?string
     */
    public function getApplication(): ?string
    {
        return null;
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    public function getConfirmedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface
    {
        return null;
    }
}
