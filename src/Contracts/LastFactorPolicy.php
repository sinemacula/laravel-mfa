<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Database\Eloquent\Collection;

/**
 * Last factor policy contract.
 *
 * Whether the identity's last confirmed factor, or the last one an application
 * or requirement accepts, may be removed by the identity acting on the
 * application. It is asked before the removal and again when it commits, so
 * required MFA cannot be turned off by the person it applies to.
 *
 * The caller supplies the identity's factor state each time: a snapshot read
 * without a lock the first time, and the factors as stored under the identity's
 * lock the second. A policy decides on what it is given and takes no factor
 * lock of its own, since the first ask may run inside a caller's transaction
 * before the identity's lock is held, and taking a factor's lock there would
 * break the lock order.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LastFactorPolicy
{
    /**
     * Whether the factor, the last of its kind for the identity, may be
     * removed, on the identity's factor state as given.
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
