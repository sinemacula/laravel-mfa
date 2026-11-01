<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Subject type resolver contract.
 *
 * Whether an identity is a person. Only a person's identity can hold factors: a
 * machine (an API client or a service account) has no interactive sign-in, and
 * every operation refuses it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SubjectTypeResolver
{
    /**
     * Whether the identity is a person.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    public function isPerson(Authenticatable $identity): bool;
}
