<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\Base32;
use SineMacula\Laravel\Mfa\Drivers\TotpParameters;

/**
 * Stands in for a TOTP authenticator app: a test factor's secret and
 * attributes, and the code it shows now or `$steps` time steps away.
 *
 * Reads the driver's clock, so `Carbon::setTestNow()` freezes it. A time step
 * is accepted once per factor; for another code, move the clock or pass
 * `$steps`. The secret is RFC 6238's public test key. Not for production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthenticatorApp
{
    /** @var string The RFC 6238 SHA-1 test key `12345678901234567890`, in Base32. */
    public const string SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    /** @var array<string, int|string> A TOTP factor with the secret and default parameters. */
    public const array FACTOR = [
        'type'           => 'totp',
        'secret'         => self::SECRET,
        'totp_algorithm' => 'sha1',
        'totp_digits'    => 6,
        'totp_period'    => 30,
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Code the app shows `$steps` time steps from now.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  int  $steps
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function code(Factor $factor, int $steps = 0): string
    {
        if ($factor->getType() !== 'totp') {
            throw new \InvalidArgumentException('The factor is not a TOTP factor, so no authenticator app shows a code for it.');
        }

        $parameters = TotpParameters::fromFactor($factor);

        if ($parameters === null) {
            throw new \InvalidArgumentException('The factor holds no valid TOTP parameters.');
        }

        $key = Base32::decode($factor->getSecret() ?? '');

        if ($key === null || $key === '') {
            throw new \InvalidArgumentException('The factor holds no usable Base32 secret.');
        }

        return $parameters->code($key, $parameters->stepAt(CarbonImmutable::now()->getTimestamp()) + $steps);
    }
}
