<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The `mfa.enrollment` settings, read and bounds-checked on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentSettings
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
     * Minutes a pending factor can be confirmed before it is pruned.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlMinutes(): int
    {
        return IntegerSetting::read($this->config, 'mfa.enrollment.ttl_minutes', 15, 1, 60);
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAttempts(): int
    {
        return IntegerSetting::read($this->config, 'mfa.enrollment.max_attempts', 5, 1, 10);
    }

    /**
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->ttlMinutes();
        $this->maxAttempts();
    }
}
