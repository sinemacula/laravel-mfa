<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http\Middleware;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Marks a route as one `mfa` does not gate, such as the routes that complete a
 * verification or a bootstrap enrolment, in every form `mfa` takes.
 *
 * It only passes the request on. `EnsureMfaRequirementIsMet` reads the mark
 * from the route's resolved middleware rather than a request attribute, so the
 * order the two run in does not matter, `withoutMiddleware()` is honoured and
 * nothing a request carries can claim it. It grants nothing: whatever helper
 * the route calls checks for itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ExemptFromMfa
{
    /**
     * Pass the request on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        return $next($request);
    }
}
