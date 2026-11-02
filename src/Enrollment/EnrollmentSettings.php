<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The enrolment settings in `mfa.enrollment`, read on every call and validated
 * as they are read: how long a pending factor waits to be confirmed, and how
 * many wrong codes abandon it. A value outside its bounds fails closed with an
 * `InvalidArgumentException` naming the key; the package checks it when it
 * boots and `mfa:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentSettings
{
    /** @var string The key of the pending enrolment lifetime. */
    private const string TTL_MINUTES = 'mfa.enrollment.ttl_minutes';

    /** @var string The key of the enrolment's own attempt cap. */
    private const string MAX_ATTEMPTS = 'mfa.enrollment.max_attempts';

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
     * How long a pending factor can be confirmed after its enrolment starts, in
     * minutes, 1 to 60; it is abandoned and pruned after that.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlMinutes(): int
    {
        return IntegerSetting::read($this->config, self::TTL_MINUTES, 15, 1, 60);
    }

    /**
     * How many wrong codes a pending factor takes before it is abandoned, 1 to
     * 10.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAttempts(): int
    {
        return IntegerSetting::read($this->config, self::MAX_ATTEMPTS, 5, 1, 10);
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
        $this->ttlMinutes();
        $this->maxAttempts();
    }
}
