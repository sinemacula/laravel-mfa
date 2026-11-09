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
 * Builds the refusal that asks a caller to step up: the requirement as given,
 * the factors offered to the caller, the operation it is labelled with, and
 * whether the identity has a confirmed factor.
 *
 * The requirement is taken as the deciding site composed it; nothing is added
 * here, and the operation only labels the refusal, adding no freshness. The
 * identity whose factors are reported is the pending session's, whatever it is,
 * as the gate reports it, or otherwise the person signed in; any other caller
 * serving nobody, or naming an identity that is not a person, has no confirmed
 * factor.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StepUpRefusal
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the offers, the resolver and the configuration are resolved from. */
        private Container $container,
    ) {}

    /**
     * The refusal asking the caller to meet the requirement.
     *
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
     * Whether the identity the caller is served as has a factor whose stored
     * status is exactly `confirmed` (see `Factors\ConfirmedFactors`): the
     * pending session's identity, or the person signed in.
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
