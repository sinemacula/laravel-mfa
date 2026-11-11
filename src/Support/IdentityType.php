<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The type an identity is recorded under in factors, proofs and events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class IdentityType
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The morph class for an Eloquent identity, so a morph map is honoured.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     */
    public static function of(Authenticatable $identity): string
    {
        return $identity instanceof Model
            // @phpstan-ignore staticMethod.dynamicCall
            ? $identity->getMorphClass()
            : $identity::class;
    }
}
