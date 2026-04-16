<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use Symfony\Component\HttpFoundation\Response;

/**
 * Require MFA middleware.
 *
 * Checks whether the current identity must complete multi-factor
 * authentication. Throws an exception if MFA is required but has
 * not been verified, or if a previous verification has expired.
 *
 * This middleware does not render responses; it throws exceptions
 * for the consuming application to handle via its exception
 * handler.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class RequireMfa
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException
     */
    public function handle(Request $request, \Closure $next): Response
    {
        if ($request->attributes->get('skip_mfa', false)) {
            return $next($request);
        }

        if (!Mfa::shouldUse()) {
            return $next($request);
        }

        $factors = $this->resolveFactorsData();

        if (!Mfa::isSetup()) {
            throw new MfaRequiredException($factors);
        }

        if (Mfa::hasExpired()) {
            throw new MfaExpiredException($factors);
        }

        return $next($request);
    }

    /**
     * Resolve the factors data for the exception payload.
     *
     * @return array<string, mixed>
     */
    private function resolveFactorsData(): array
    {
        $factors = Mfa::getFactors();

        if ($factors === null) {
            return [];
        }

        return $factors->toArray();
    }
}
