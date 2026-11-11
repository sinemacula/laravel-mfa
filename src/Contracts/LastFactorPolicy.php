<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Database\Eloquent\Collection;

/**
 * Whether an identity may remove its last confirmed or last accepted factor, so
 * required MFA cannot be turned off by the person it applies to.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LastFactorPolicy
{
    /**
     * Decide on the factors given and take no factor lock; the first ask may
     * run before the identity's lock is held.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return bool
     *
     * @formatter:on
     */
    public function allowsRemoval(MultiFactorAuthenticatable $identity, string $application, Factor $factor, Collection $factors): bool;
}
