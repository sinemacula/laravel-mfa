<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http\Middleware;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Proofs\ProofSettings;
use Symfony\Component\HttpFoundation\Response;

/**
 * Require MFA middleware.
 *
 * Gates incoming requests behind a valid MFA verification: a proof of an
 * additional factor or a recovery code recorded on the identity's current
 * sign-in, read through `Mfa::proofs()`. Throws one of two structured
 * exceptions depending on the identity's state, so the consuming application
 * can render different UIs for each case:
 *
 * - No factors set up OR factors exist but the current sign-in holds no such
 *   proof → `MfaRequiredException`
 * - The newest such proof has aged past the configured window, or is dated in
 *   the future → `MfaExpiredException`
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
 * `mfa.proofs.max_age_minutes` per route group: `mfa:5` requires a verification
 * no older than five minutes; `mfa:0` forces re-verification on every request.
 * This is the step-up lever for sensitive actions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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

        $verifiedAt = $this->lastVerifiedAt();

        if ($verifiedAt === null) {
            throw new MfaRequiredException($summaries);
        }

        if ($this->hasExpired($verifiedAt, $expiresAfter ?? $this->configuredMaxAgeMinutes())) {
            throw new MfaExpiredException($summaries);
        }

        return $next($request);
    }

    /**
     * When the newest proof of an additional factor or a recovery code on the
     * identity's current sign-in was made, or `null` when it holds none.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    private function lastVerifiedAt(): ?CarbonImmutable
    {
        $verifiedAt = null;

        foreach (Mfa::proofs() as $proof) {

            $verifies = $proof->kind === ProofKind::ADDITIONAL_FACTOR || $proof->kind === ProofKind::RECOVERY_CODE;

            if (!$verifies || ($verifiedAt !== null && !$proof->provedAt->greaterThan($verifiedAt))) {
                continue;
            }

            $verifiedAt = $proof->provedAt;
        }

        return $verifiedAt;
    }

    /**
     * Whether a verification made at the given time is too old for the window:
     * a window of zero or less treats every verification as expired, and one
     * dated in the future (clock skew or a tampered store) is never trusted.
     *
     * @param  \Carbon\CarbonImmutable  $verifiedAt
     * @param  int  $maxAgeMinutes
     * @return bool
     */
    private function hasExpired(CarbonImmutable $verifiedAt, int $maxAgeMinutes): bool
    {
        if ($maxAgeMinutes <= 0) {
            return true;
        }

        $elapsed = $verifiedAt->diffInMinutes(CarbonImmutable::now(), false);

        return $elapsed < 0 || $elapsed > $maxAgeMinutes;
    }

    /**
     * The window `mfa.proofs.max_age_minutes` configures, in minutes.
     *
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function configuredMaxAgeMinutes(): int
    {
        return (new ProofSettings(Container::getInstance()->make(Repository::class)))->maxAgeMinutes();
    }

    /**
     * Parse the route-middleware `max-age` parameter into integer minutes (or
     * null when absent).
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
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     */
    private function resolveFactorSummaries(): array
    {
        $factors = Mfa::getFactors();

        if ($factors === null) {
            return [];
        }

        /** @var list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> */
        return $factors
            ->map(static fn ($factor): FactorSummary => FactorSummary::fromFactor($factor))
            ->values()
            ->all();
    }
}
