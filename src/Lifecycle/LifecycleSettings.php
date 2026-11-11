<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The `mfa.lifecycle` settings, validated on every read; a value out of bounds
 * fails closed with an `InvalidArgumentException` naming the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleSettings
{
    /** @var string */
    private const string PRUNE_AFTER_DAYS = 'mfa.lifecycle.prune_after_days';

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call so a changed setting applies. */
        private Repository $config,
    ) {}

    /**
     * Days pruning keeps a record after it stops being usable, 1 to 3650.
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
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->pruneAfterDays();
    }
}
