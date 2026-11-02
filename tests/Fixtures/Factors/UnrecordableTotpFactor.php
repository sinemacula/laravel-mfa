<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;

/**
 * TOTP factor fixture implementing only the `Factor` read surface: it holds the
 * authenticator app's secret and the default parameters but has nowhere to
 * record an accepted time step, so the driver cannot hold it to single use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnrecordableTotpFactor extends AbstractFactorStub
{
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
     * Return the authenticator app's secret.
     *
     * @return string
     */
    #[\Override]
    public function getSecret(): string
    {
        return AuthenticatorApp::SECRET;
    }

    /**
     * Return the default HMAC algorithm.
     *
     * @return string
     */
    #[\Override]
    public function getTotpAlgorithm(): string
    {
        return 'sha1';
    }

    /**
     * Return the default number of digits.
     *
     * @return int
     */
    #[\Override]
    public function getTotpDigits(): int
    {
        return 6;
    }

    /**
     * Return the default period.
     *
     * @return int
     */
    #[\Override]
    public function getTotpPeriod(): int
    {
        return 30;
    }
}
