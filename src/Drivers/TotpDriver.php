<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\MissingDriverDependencyException;

/**
 * TOTP factor driver.
 *
 * Verifies time-based one-time passwords using the pragmarx/google2fa
 * library. The library is a suggested dependency and is checked at
 * runtime so the package remains lightweight for applications that
 * do not use TOTP.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class TotpDriver implements FactorDriver
{
    /** @var object The Google2FA instance */
    private readonly object $google2fa;

    /**
     * Create a new TOTP driver instance.
     *
     * @param  int  $window
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MissingDriverDependencyException
     */
    public function __construct(
        private readonly int $window = 1,
    ) {
        // @codeCoverageIgnoreStart
        // This branch only fires when `pragmarx/google2fa` is absent,
        // which cannot be exercised under the package's own test suite
        // without uninstalling the dev dependency. The exception contract
        // is still asserted elsewhere via a dedicated class-exists mock.
        if (!class_exists(\PragmaRX\Google2FA\Google2FA::class)) {
            $message = 'The pragmarx/google2fa package is required for the '
                . 'TOTP MFA driver. Install it via: composer '
                . 'require pragmarx/google2fa';

            throw new MissingDriverDependencyException($message);
        }
        // @codeCoverageIgnoreEnd

        $this->google2fa = new \PragmaRX\Google2FA\Google2FA;
    }

    /**
     * TOTP challenges are implicit: the authenticator app generates
     * codes locally from the shared secret, so there is no server
     * action to take on challenge issuance.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void
    {
        // No-op — TOTP codes are generated client-side.
    }

    /**
     * Verify the given code against the factor's stored secret.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $secret = $factor->getSecret();

        if ($secret === null || $secret === '') {
            return false;
        }

        return (bool) $this->google2fa->verifyKey($secret, $code, $this->window);
    }

    /**
     * Generate a new TOTP shared secret.
     *
     * @return string
     */
    public function generateSecret(): string
    {
        /** @var string */
        return $this->google2fa->generateSecretKey();
    }
}
