<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;

/**
 * An `ApplicationResolver` also asked with the guard wherever one is known, so
 * a proof begun at sign-in binds to the application its caller is served on.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface GuardApplicationResolver extends ApplicationResolver
{
    /**
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return string
     */
    public function resolveForGuard(Request $request, string $guard): string;
}
