<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors\Concerns;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * The `Factor` accessors a test double rarely needs to vary, answering as a
 * confirmed factor no one has used yet: no credential reference, no TOTP
 * parameters or accepted step, not preferred, no failures, not disabled, no
 * application and no times.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReportsUsableFactorDefaults
{
    /**
     * No credential reference.
     *
     * @return ?string
     */
    public function getCredentialReference(): ?string
    {
        return null;
    }

    /**
     * No TOTP algorithm.
     *
     * @return ?string
     */
    public function getTotpAlgorithm(): ?string
    {
        return null;
    }

    /**
     * No TOTP digits.
     *
     * @return ?int
     */
    public function getTotpDigits(): ?int
    {
        return null;
    }

    /**
     * No TOTP period.
     *
     * @return ?int
     */
    public function getTotpPeriod(): ?int
    {
        return null;
    }

    /**
     * No accepted step.
     *
     * @return ?int
     */
    public function getLastAcceptedStep(): ?int
    {
        return null;
    }

    /**
     * Confirmed.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     */
    public function getStatus(): FactorStatus
    {
        return FactorStatus::CONFIRMED;
    }

    /**
     * Confirmed.
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->getStatus() === FactorStatus::CONFIRMED;
    }

    /**
     * Not preferred.
     *
     * @return bool
     */
    public function isPreferred(): bool
    {
        return false;
    }

    /**
     * No failures.
     *
     * @return int
     */
    public function getConsecutiveFailures(): int
    {
        return 0;
    }

    /**
     * Not disabled.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getDisabledAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * No application.
     *
     * @return ?string
     */
    public function getApplication(): ?string
    {
        return null;
    }

    /**
     * Never confirmed at a known time.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getConfirmedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Never used.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface
    {
        return null;
    }
}
