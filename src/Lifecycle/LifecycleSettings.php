<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The lifecycle settings in `mfa.lifecycle`, read on every call and validated
 * as they are read: how long pruning keeps the records it removes (abandoned
 * enrolments, expired codes, used and replaced recovery codes). A value outside
 * its bounds fails closed with an `InvalidArgumentException` naming the key;
 * the package checks it when it boots and `mfa:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleSettings
{
    /** @var string The key of the retention. */
    private const string PRUNE_AFTER_DAYS = 'mfa.lifecycle.prune_after_days';

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
     * How many days pruning keeps a record after it stops being usable, 1 to
     * 3650.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function pruneAfterDays(): int
    {
        return IntegerSetting::read($this->config, self::PRUNE_AFTER_DAYS, 30, 1, 3650);
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
        $this->pruneAfterDays();
    }
}
