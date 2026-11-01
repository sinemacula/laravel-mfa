<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The identity the package's services act for: whoever `Auth::user()` returns
 * on the default guard, when it is MFA-capable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CurrentIdentity
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Resolve the currently authenticated identity if it is MFA-capable.
     *
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    public static function resolve(): ?MultiFactorAuthenticatable
    {
        $identity = Auth::user();

        return $identity instanceof MultiFactorAuthenticatable
            ? $identity
            : null;
    }

    /**
     * The type an identity is recorded under on a factor's owner columns: its
     * morph class for an Eloquent identity, so an application's morph map is
     * honoured, and its class name otherwise.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     */
    public static function typeOf(Authenticatable $identity): string
    {
        return $identity instanceof Model
            // @phpstan-ignore staticMethod.dynamicCall
            ? $identity->getMorphClass()
            : $identity::class;
    }
}
