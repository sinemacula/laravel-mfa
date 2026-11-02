<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Chooses the request's locale, as an application's own middleware would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChooseLocale
{
    /**
     * Set the locale and carry on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @param  string  $locale
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next, string $locale): Response
    {
        app()->setLocale($locale);

        return $next($request);
    }
}
