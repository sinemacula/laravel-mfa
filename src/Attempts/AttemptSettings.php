<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The `mfa.attempts` settings, read and bounds-checked on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptSettings
{
    /** @var string */
    private const string PREFIX = 'mfa.attempts.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, minimum and maximum per setting. */
    private const array NUMBERS = [
        'factor_limit'    => [5, 1, 20],
        'identity_limit'  => [20, 1, 100],
        'ip_limit'        => [100, 1, 10000],
        'window_seconds'  => [900, 60, 86400],
        'lockout_seconds' => [900, 60, 86400],
        'failure_ceiling' => [100, 1, 100],
    ];

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function factorLimit(): int
    {
        return $this->number('factor_limit');
    }

    /**
     * Failures across the identity's factors and recovery codes in the window.
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
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ipLimit(): int
    {
        return $this->number('ip_limit');
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function windowSeconds(): int
    {
        return $this->number('window_seconds');
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function lockoutSeconds(): int
    {
        return $this->number('lockout_seconds');
    }

    /**
     * Consecutive failures that disable a factor; capped at 100 per NIST SP
     * 800-63B-4.
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
