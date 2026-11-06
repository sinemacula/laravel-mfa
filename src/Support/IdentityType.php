<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * The type an identity is recorded under on a factor's owner columns, in its
 * proofs and in its events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityType
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The identity's type: its morph class for an Eloquent identity, so an
     * application's morph map is honoured, and its class name otherwise.
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
