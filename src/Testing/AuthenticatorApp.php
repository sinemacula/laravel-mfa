<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\Base32;
use SineMacula\Laravel\Mfa\Drivers\TotpParameters;

/**
 * Stands in for the authenticator app a TOTP factor is enrolled in: the secret
 * and parameters a test factor is stored with, and the code the app shows for a
 * factor now or a number of time steps away.
 *
 * It reads the driver's clock, so `Carbon::setTestNow()` is the frozen time.
 * The driver accepts a time step once per factor, so a code already accepted
 * replays: for another, a test moves the clock or passes `$steps`.
 *
 * The secret is the 20-byte key of RFC 6238 Appendix B, so a code can be
 * checked against the published test vectors by hand. It is public test
 * material, and no enrolment ever defaults to it. Not for production use.
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

    /** @var array<string, int|string> The attributes of a TOTP factor enrolled with the secret and the default parameters. */
    public const array FACTOR = [
        'type'           => 'totp',
        'secret'         => self::SECRET,
        'totp_algorithm' => 'sha1',
        'totp_digits'    => 6,
        'totp_period'    => 30,
    ];

    /** @var string The type of the factors a code can be made for. */
    private const string TOTP = 'totp';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The code the factor's authenticator app shows the given number of time
     * steps from now.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  int  $steps
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function code(Factor $factor, int $steps = 0): string
    {
        if ($factor->getType() !== self::TOTP) {
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
