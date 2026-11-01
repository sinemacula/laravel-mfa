<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The proof settings in `mfa.proofs`, read on every call and validated as they
 * are read: how long a recorded verification counts before the person must
 * verify again. A value outside its bounds fails closed with an
 * `InvalidArgumentException` naming the key; the package checks it when it
 * boots and `mfa:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofSettings
{
    /** @var string The key of the verification lifetime. */
    private const string MAX_AGE_MINUTES = 'mfa.proofs.max_age_minutes';

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
     * How long a recorded verification counts, in minutes, 0 to 525600 (a
     * year); 0 counts none, so every request needs a fresh one.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAgeMinutes(): int
    {
        return IntegerSetting::read($this->config, self::MAX_AGE_MINUTES, 20160, 0, 525600);
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
        $this->maxAgeMinutes();
    }
}
