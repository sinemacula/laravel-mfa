<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The attempt settings in `mfa.attempts`, read on every call and validated as
 * they are read: the caps on failed attempts per factor, per identity and per
 * IP address, the window the identity and IP caps count over, how long a
 * lockout lasts, and the failure ceiling at which a factor is disabled. A value
 * outside its bounds fails closed with an `InvalidArgumentException` naming the
 * key; the package checks them when it boots and `mfa:check` reports them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptSettings
{
    /** @var string Prefix of every attempt setting's key. */
    private const string PREFIX = 'mfa.attempts.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each setting. */
    private const array NUMBERS = [
        'factor_limit'    => [5, 1, 20],
        'identity_limit'  => [20, 1, 100],
        'ip_limit'        => [100, 1, 10000],
        'window_seconds'  => [900, 60, 86400],
        'lockout_seconds' => [900, 60, 86400],
        'failure_ceiling' => [100, 1, 100],
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
     * How many failed attempts in a row lock a factor, 1 to 20.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function factorLimit(): int
    {
        return $this->number('factor_limit');
    }

    /**
     * How many failed attempts across an identity's factors and recovery codes
     * within the window lock the identity, 1 to 100.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function identityLimit(): int
    {
        return $this->number('identity_limit');
    }

    /**
     * How many failed attempts from one IP address within the window throttle
     * it, 1 to 10000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ipLimit(): int
    {
        return $this->number('ip_limit');
    }

    /**
     * The window the identity and IP caps count over, in seconds, 60 to 86400.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function windowSeconds(): int
    {
        return $this->number('window_seconds');
    }

    /**
     * How long a lockout lasts, in seconds, 60 to 86400.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function lockoutSeconds(): int
    {
        return $this->number('lockout_seconds');
    }

    /**
     * How many consecutive failures disable a factor until the person proves
     * another, it is rebound or the identity is reset, 1 to 100 (the most NIST
     * SP 800-63B-4 allows).
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function failureCeiling(): int
    {
        return $this->number('failure_ceiling');
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
        foreach (array_keys(self::NUMBERS) as $key) {
            $this->number($key);
        }
    }

    /**
     * Read a setting from its least to its greatest value.
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
