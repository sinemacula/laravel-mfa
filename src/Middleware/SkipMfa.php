<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Middleware;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Skip MFA middleware.
 *
 * Marks the current request to bypass MFA checks. This should be applied to
 * routes that handle the MFA verification flow itself, preventing circular
 * enforcement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class SkipMfa
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        $request->attributes->set('skip_mfa', true);

        return $next($request);
    }
}
