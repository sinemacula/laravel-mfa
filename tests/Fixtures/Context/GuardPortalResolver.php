<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * Names a portal per guard, so a test can tell an application named through the
 * guard from the default guard's one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GuardPortalResolver implements GuardApplicationResolver
{
    /**
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return 'web-portal';
    }

    /**
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
