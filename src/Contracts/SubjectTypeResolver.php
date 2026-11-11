<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Whether an identity is a person; only a person can hold factors, so every
 * operation refuses a machine.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SubjectTypeResolver
{
    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    public function isPerson(Authenticatable $identity): bool;
}
