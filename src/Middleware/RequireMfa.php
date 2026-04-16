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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class RequireMfa
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
        if ($request->attributes->get('skip_mfa', false) === true) {
            return $next($request);
        }

        if (!Mfa::shouldUse()) {
            return $next($request);
        }

        $summaries = $this->resolveFactorSummaries();

        if (!Mfa::isSetup()) {
            throw new MfaRequiredException($summaries);
        }

        if (!Mfa::hasEverVerified()) {
            throw new MfaRequiredException($summaries);
        }

        if (Mfa::hasExpired()) {
            throw new MfaExpiredException($summaries);
        }

        return $next($request);
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
