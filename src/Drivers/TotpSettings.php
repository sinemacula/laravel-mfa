<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The TOTP settings in `mfa.totp`, read on every call and validated as they are
 * read: the algorithm, digits and period new enrolments use, the window an
 * application that sets none of its own accepts, and the issuer an
 * authenticator app shows. A value outside its bounds fails closed with an
 * `InvalidArgumentException` naming the key; the package checks them when it
 * boots and `mfa:check` reports them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TotpSettings
{
    /** @var string Prefix of every TOTP setting's key. */
    private const string PREFIX = 'mfa.totp.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting. */
    private const array NUMBERS = [
        'digits' => [6, TotpParameters::MIN_DIGITS, TotpParameters::MAX_DIGITS],
        'period' => [30, TotpParameters::MIN_PERIOD, TotpParameters::MAX_PERIOD],
        'window' => [1, 0, 3],
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The HMAC algorithm new enrolments use: `sha1` (the default, which every
     * authenticator app supports), `sha256` or `sha512`.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function algorithm(): string
    {
        $algorithm = $this->config->get(self::PREFIX . 'algorithm', 'sha1');

        if (!in_array($algorithm, TotpParameters::ALGORITHMS, true)) {
            throw new \InvalidArgumentException(sprintf('%salgorithm must be one of %s.', self::PREFIX, implode(', ', TotpParameters::ALGORITHMS)));
        }

        return $algorithm;
    }

    /**
     * The number of digits in a code for new enrolments, 6 to 8.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function digits(): int
    {
        return $this->number('digits');
    }

    /**
     * How long each code lasts for new enrolments, in seconds, 15 to 120.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function period(): int
    {
        return $this->number('period');
    }

    /**
     * How many time steps either side of the current one are accepted, 0 to 3,
     * by an application that sets no window of its own.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function window(): int
    {
        return $this->number('window');
    }

    /**
     * How many time steps either side of the current one the named application
     * accepts: its own `totp_window`, or `window()` when it sets none.
     *
     * @param  string  $application
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function windowFor(string $application): int
    {
        return (new ApplicationSettings($this->config, $application))->totpWindow();
    }

    /**
     * The issuer an authenticator app shows for a new enrolment that names none
     * of its own: `mfa.totp.issuer`, or the application's name without one.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function issuer(): string
    {
        $issuer = $this->configuredIssuer() ?? $this->config->get('app.name');

        if (!is_string($issuer)) {
            throw new \InvalidArgumentException(sprintf('Set %sissuer or app.name: an authenticator app must show an issuer.', self::PREFIX));
        }

        return $issuer;
    }

    /**
     * The algorithm, digits and period a new enrolment is made with, stored
     * with its factor.
     *
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpParameters
     *
     * @throws \InvalidArgumentException
     */
    public function parameters(): TotpParameters
    {
        return new TotpParameters($this->algorithm(), $this->digits(), $this->period());
    }

    /**
     * Read every setting, failing closed on the first that is out of bounds.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->algorithm();
        $this->digits();
        $this->period();
        $this->window();
        $this->configuredIssuer();
    }

    /**
     * The issuer `mfa.totp.issuer` sets, if any, which must be a non-empty
     * string.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function configuredIssuer(): ?string
    {
        $issuer = $this->config->get(self::PREFIX . 'issuer');

        if ($issuer !== null && (!is_string($issuer) || trim($issuer) === '')) {
            throw new \InvalidArgumentException(sprintf('%sissuer must be a non-empty string.', self::PREFIX));
        }

        return $issuer;
    }

    /**
     * Read a numeric setting from its least to its greatest value.
     *
     * @param  string  $key
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $key): int
    {
        [$default, $least, $most] = self::NUMBERS[$key];

        return IntegerSetting::read($this->config, self::PREFIX . $key, $default, $least, $most);
    }
}
