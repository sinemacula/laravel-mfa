<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * The default `FreshnessGate`, which works from the proof store alone: the
 * current identity's sign-in on the current application is fresh for an
 * operation when the bound `RequirementCheck` finds its recorded proofs meet
 * the operation's requirement (see `OperationRequirements::effective()`), the
 * stricter of the application's configured one and the caller's.
 *
 * It is not fresh without an identity, without a requirement, without a sign-in
 * the store knows of, or without a first factor on it: proofs are judged only
 * after the sign-in's first factor. The first factor is the one the store
 * recorded; only when it holds none is the bound `FirstFactorResolver` asked,
 * and its answer counts only when it is a first factor of the identity on the
 * application, bound to the current sign-in, made under the identity's current
 * verification generation and not after now (see `Context\SessionFirstFactor`).
 * Only a proof's own time counts, so refreshing or regenerating the session
 * never renews freshness.
 *
 * Stateless: the configuration, the store and every collaborator are resolved
 * on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredFreshnessGate implements FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configuration, the store and the check are resolved from. */
        private Container $container,
    ) {}

    /**
     * Whether the current session is fresh for the operation.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        return $this->evaluation($operation, $callerRequirement)?->meetsRequirement() === true;
    }

    /**
     * When the current session stops being fresh for the operation, on the
     * proofs it holds now: `null` when it is not fresh, and when the bound
     * policy reports no such time for a requirement bounded by a maximum age.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function freshUntil(string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        return $this->evaluation($operation, $callerRequirement)?->metUntil;
    }

    /**
     * What the session's recorded proofs add up to against the operation's
     * requirement, or `null` without an identity or a requirement.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function evaluation(string $operation, ?Requirement $callerRequirement): ?Evaluation
    {
        $application = $this->container->make(ProofService::class)->application();
        $operations  = new OperationRequirements($this->container->make(Repository::class));
        $requirement = $operations->effective($application, $operation, $callerRequirement);
        $identity    = CurrentIdentity::resolve();

        if ($requirement === null || $identity === null) {
            return null;
        }

        $proofs = $this->container->make(SessionFirstFactor::class)->proofs($identity, $application);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs);
    }
}
