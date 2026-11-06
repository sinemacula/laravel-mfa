<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;

/**
 * Guard application resolver contract.
 *
 * An `ApplicationResolver` that also names the application a request is for
 * through a given guard. Bound as the `ApplicationResolver`, it is asked with
 * the guard wherever one is known: the caller of a request built through a
 * named guard, and a sign-in or sign-out on a guard other than the default.
 * Both ask the same way, so a proof begun at sign-in is bound to the
 * application its caller is served on.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface GuardApplicationResolver extends ApplicationResolver
{
    /**
     * The application the request is for through the guard.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return string
     */
    public function resolveForGuard(Request $request, string $guard): string;
}
