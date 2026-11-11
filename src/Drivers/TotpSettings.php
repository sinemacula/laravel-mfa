<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The `mfa.totp` settings, read on every call and failing closed when out of
 * bounds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TotpSettings
{
    /** @var string */
    private const string PREFIX = 'mfa.totp.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting. */
    private const array NUMBERS = [
        'digits' => [6, TotpParameters::MIN_DIGITS, TotpParameters::MAX_DIGITS],
        'period' => [30, TotpParameters::MIN_PERIOD, TotpParameters::MAX_PERIOD],
        'window' => [1, 0, 3],
    ];

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
     * Defaults to `sha1`, which every authenticator app supports.
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
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function digits(): int
    {
        return $this->number('digits');
    }

    /**
     * In seconds.
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
     * Steps either side of the current one, for an application that sets no
     * window of its own.
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
     * `mfa.totp.issuer`, or `app.name` without one.
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
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpParameters
     *
     * @throws \InvalidArgumentException
     */
    public function parameters(): TotpParameters
    {
        return new TotpParameters($this->algorithm(), $this->digits(), $this->period());
    }

    /**
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
