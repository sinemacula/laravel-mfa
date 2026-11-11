<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;

/**
 * A TOTP factor with nowhere to record an accepted time step, so the driver
 * cannot hold it to single use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnrecordableTotpFactor extends AbstractFactorStub
{
    /**
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'totp';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getSecret(): string
    {
        return AuthenticatorApp::SECRET;
    }

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
}
