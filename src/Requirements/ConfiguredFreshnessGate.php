<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;

/**
 * The default `FreshnessGate`, judged on the sign-in's recorded proofs. Only a
 * proof's own time counts, so refreshing the session never renews freshness.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredFreshnessGate implements FreshnessGate
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Collaborators are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
    {
        return $this->evaluation($caller, $operation, $callerRequirement)?->meetsRequirement() === true;
    }

    /**
     * `null` when not fresh, or when the policy reports no end.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        return $this->evaluation($caller, $operation, $callerRequirement)?->metUntil;
    }

    /**
     * The stricter of the configured and the caller's requirement, either alone
     * when the other is absent.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        return (new OperationRequirements($this->container->make(Repository::class)))->effective($caller->application, $operation, $callerRequirement);
    }

    /**
     * `null` without a requirement or an active person to serve.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function evaluation(CallerContext $caller, string $operation, ?Requirement $callerRequirement): ?Evaluation
    {
        $application = $caller->application;
        $requirement = $this->requirement($caller, $operation, $callerRequirement);
        $identity    = $this->container->make(CallerContextResolver::class)->resolve($caller, null)?->identity;

        if ($requirement === null || $identity === null || !$this->container->make(ActiveStateResolver::class)->isActive($identity)) {
            return null;
        }

        $proofs = $this->container->make(SessionFirstFactor::class)->proofs($identity, $application);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs);
    }
}
