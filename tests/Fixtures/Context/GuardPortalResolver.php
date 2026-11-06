<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * Names a portal for each guard, so a test can tell an application named
 * through the guard from one named without it, which is the default guard's
 * portal, as a resolver reading only the request would name it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GuardPortalResolver implements GuardApplicationResolver
{
    /**
     * The application of the request without a guard: the default guard's
     * portal.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return 'web-portal';
    }

    /**
     * The application of the request through the guard: the guard's portal.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return string
     */
    #[\Override]
    public function resolveForGuard(Request $request, string $guard): string
    {
        return $guard . '-portal';
    }
}
