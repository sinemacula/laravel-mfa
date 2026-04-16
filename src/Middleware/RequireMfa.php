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
 * Gates incoming requests behind a valid MFA verification. Throws one
 * of two structured exceptions depending on the identity's state, so
 * the consuming application can render different UIs for each case:
 *
 * - No factors set up OR factors exist but the identity has never
 *   verified → `MfaRequiredException`
 * - Prior verification exists but has aged past the configured expiry
 *   window → `MfaExpiredException`
 *
 * Both exceptions carry a list of `FactorSummary` records with masked
 * delivery destinations so they are safe to ship through JSON response
 * bodies and log sinks.
 *
 * Requests flagged with the `skip_mfa` request attribute (set by
 * `SkipMfa`) bypass enforcement entirely — used on the verification
 * endpoints themselves to avoid circular enforcement.
 *
 * Accepts an optional route-middleware parameter to override the
 * configured `default_expiry` for a single route group — `mfa:5` gates
 * the route behind a verification no older than five minutes; `mfa:0`
 * forces re-verification on every request. This is the step-up
 * enforcement lever for sensitive actions that should not rely on the
 * permissive global expiry window.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class RequireMfa
{
    /**
     * Handle an incoming request.
     *
     * Laravel passes route-middleware parameters as strings, so the
     * optional `$maxAgeMinutes` argument is typed `?string` and parsed
     * here. A non-numeric or negative value is a programmer error and
     * raises `InvalidArgumentException` so the misconfiguration surfaces
     * loudly the first time a covered route is hit.
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
    public function handle(
        Request $request,
        \Closure $next,
        ?string $maxAgeMinutes = null,
    ): Response {
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
     * Parse the route-middleware `max-age` parameter into an integer
     * minutes value (or null when absent).
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

        if (!is_numeric($maxAgeMinutes) || str_contains($maxAgeMinutes, '.')) {
            throw new \InvalidArgumentException(sprintf('RequireMfa middleware max-age parameter must be a non-negative integer; received "%s".', $maxAgeMinutes));
        }

        $value = (int) $maxAgeMinutes;

        if ($value < 0) {
            throw new \InvalidArgumentException(sprintf('RequireMfa middleware max-age parameter must be a non-negative integer; received "%s".', $maxAgeMinutes));
        }

        return $value;
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
