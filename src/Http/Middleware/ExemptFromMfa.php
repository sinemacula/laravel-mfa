<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http\Middleware;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Marks a route `mfa` does not gate, such as verification or bootstrap
 * enrolment. Read from the route's middleware, so order does not matter and no
 * request can claim it. It grants nothing; the route's helpers still check for
 * themselves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ExemptFromMfa
{
    /**
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        return $next($request);
    }
}
