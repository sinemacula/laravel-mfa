<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The `mfa.no-store` middleware: sends every response of the routes it is
 * placed on with `Cache-Control: no-store` and `Pragma: no-cache`, replacing
 * whatever caching the route allowed.
 *
 * Place it on the routes that start an enrolment or generate recovery codes,
 * so the one response that shows a secret is never stored, however the route
 * builds it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NoStore
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
        return SecretResponse::withoutStoring($next($request));
    }
}
