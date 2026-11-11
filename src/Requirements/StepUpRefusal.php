<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Factors\ConfirmedFactors;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;

/**
 * Builds the refusal asking a caller to step up; the requirement is taken as
 * the deciding site composed it, and the operation only labels it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StepUpRefusal
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?string  $operation
     * @return \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function of(CallerContext $caller, Requirement $requirement, ?string $operation): InsufficientAuthenticationException
    {
        $offered = $this->container->make(FactorOffers::class)->offered($caller);

        return new InsufficientAuthenticationException($requirement, $offered, $operation, $this->hasConfirmedFactor($caller));
    }

    /**
     * Whether the pending session's identity, or the person signed in, holds a
     * factor stored as exactly `confirmed`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function hasConfirmedFactor(CallerContext $caller): bool
    {
        $identity = $caller->pending->identity ?? $this->container->make(CallerContextResolver::class)->resolve($caller, null)?->identity;

        return $identity !== null && ConfirmedFactors::isHeldBy($identity, $this->container->make(Repository::class));
    }
}
