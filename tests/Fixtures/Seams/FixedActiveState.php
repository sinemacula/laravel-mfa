<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * A faulty active state resolver, for proving the contract kit rejects it: one
 * that gives the same answer for everyone, active or not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedActiveState implements ActiveStateResolver
{
    /**
     * Constructor.
     *
     * @param  bool  $active
     */
    public function __construct(

        /** The answer given for everyone. */
        private bool $active,
    ) {}

    /**
     * Whether the identity is active: the same answer for everyone.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return $this->active;
    }
}
