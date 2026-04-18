<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Symfony\Component\HttpFoundation\Response;

/**
 * Require MFA middleware.
 *
 * Gates incoming requests behind a valid MFA verification. Throws one of two
 * structured exceptions depending on the identity's state, so the consuming
 * application can render different UIs for each case:
 *
 * - No factors set up OR factors exist but the identity has never
 *   verified → `MfaRequiredException`
 * - Prior verification exists but has aged past the configured expiry
 *   window → `MfaExpiredException`
 *
 * Both exceptions carry a list of `FactorSummary` records with masked delivery
 * destinations so they are safe to ship through JSON response bodies and log
 * sinks.
 *
 * Requests flagged with the `skip_mfa` request attribute (set by `SkipMfa`)
 * bypass enforcement entirely — used on the verification endpoints themselves
 * to avoid circular enforcement.
 *
 * Optional route-middleware parameter overrides the configured
 * `default_expiry` per route group: `mfa:5` requires a verification no older
 * than five minutes; `mfa:0` forces re-verification on every request. This is
 * the step-up lever for sensitive actions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class RequireMfa
{
    /**
     * Handle an incoming request.
     *
     * Laravel passes route-middleware parameters as strings, so the optional
     * `$maxAgeMinutes` argument is typed `?string` and parsed here. A
     * non-numeric or negative value is a programmer error and raises
     * `InvalidArgumentException` so the misconfiguration surfaces loudly the
     * first time a covered route is hit.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @param  ?string  $maxAgeMinutes
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException
     * @throws \InvalidArgumentException
     */
    public function handle(Request $request, \Closure $next, ?string $maxAgeMinutes = null): Response
    {
        if ($request->attributes->get('skip_mfa', false) === true) {
            return $next($request);
        }

        if (!Mfa::shouldUse()) {
            return $next($request);
        }

        $expiresAfter = $this->parseMaxAgeMinutes($maxAgeMinutes);

        $summaries = $this->resolveFactorSummaries();

        if (!Mfa::isSetup()) {
            throw new MfaRequiredException($summaries);
        }

        if (!Mfa::hasEverVerified()) {
            throw new MfaRequiredException($summaries);
        }

        if (Mfa::hasExpired($expiresAfter)) {
            throw new MfaExpiredException($summaries);
        }

        return $next($request);
    }

    /**
     * Parse the route-middleware `max-age` parameter into integer minutes
     * (or null when absent).
     *
     * Accepts decimal-digit strings only — `is_numeric` would pass scientific
     * notation, leading signs, whitespace, and decimals, none of which are
     * valid as a route parameter. The strict regex keeps a typo in a route
     * definition loud rather than silently coerced.
     *
     * @param  ?string  $maxAgeMinutes
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    private function parseMaxAgeMinutes(?string $maxAgeMinutes): ?int
    {
        if ($maxAgeMinutes === null) {
            return null;
        }

        if (preg_match('/^\d+$/', $maxAgeMinutes) !== 1) {
            throw new \InvalidArgumentException(sprintf('RequireMfa middleware max-age parameter must be a non-negative integer; received "%s".', $maxAgeMinutes));
        }

        return (int) $maxAgeMinutes;
    }

    /**
     * Build the factor-summary payload for exception dispatch.
     *
     * @return list<\SineMacula\Laravel\Mfa\Support\FactorSummary>
     */
    private function resolveFactorSummaries(): array
    {
        $factors = Mfa::getFactors();

        if ($factors === null) {
            return [];
        }

        /** @var list<\SineMacula\Laravel\Mfa\Support\FactorSummary> */
        return $factors
            ->map(static fn ($factor): FactorSummary => FactorSummary::fromFactor($factor))
            ->values()
            ->all();
    }
}
