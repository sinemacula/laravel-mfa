<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Gives the same answer for everyone, for proving the contract kit rejects it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedActiveState implements ActiveStateResolver
{
    /**
     * @param  bool  $active
     */
    public function __construct(

        /** The answer given for everyone. */
        private bool $active,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return $this->active;
    }
}
