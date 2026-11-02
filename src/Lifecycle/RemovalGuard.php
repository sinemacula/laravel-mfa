<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;

/**
 * What every removal of a factor checks, whichever entry point it comes
 * through, on the identity's factor state as the caller holds it:
 *
 * 1. the identity is active (`identity_inactive`);
 * 2. the factor is the identity's and was enrolled through the application
 *    acting, since an application never deletes a factor enrolled through
 *    another (`not_found`);
 * 3. it is confirmed; a pending one is cancelled or expires (`not_confirmed`);
 * 4. the session is fresh for removing a factor, and while the identity has
 *    another confirmed factor, fresh on proofs made without this one: whatever
 *    the bound gate holds the session to must be met by them too, so a step-up
 *    with the factor being removed never authorises its own removal
 *    (`not_fresh`). A person whose other factor cannot be proved is reset by
 *    someone else; the rule does not relax for them;
 * 5. the bound `LastFactorPolicy` allows it (`last_factor`).
 *
 * A refusal is an `OperationRefusedException` carrying the reason.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RemovalGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the seams are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Refuse removing the factor unless all of it holds, and return the factor.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function assertRemovable(MultiFactorAuthenticatable $identity, string $application, (EloquentFactor&Model)|null $factor, Collection $factors): EloquentFactor&Model
    {
        OperationRefusedException::unless($identity->isMfaActive(), FailureReason::IDENTITY_INACTIVE, 'The identity is inactive.');

        if ($factor === null || $factor->getApplication() !== $application) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The identity has no factor with that id enrolled through this application.');
        }

        OperationRefusedException::unless($factor->isConfirmed(), FailureReason::NOT_CONFIRMED, 'The factor is pending, so it is cancelled or expires instead.');

        $this->assertFresh($identity, $application, $factor, $factors);

        OperationRefusedException::unless(
            $this->container->make(LastFactorPolicy::class)->allowsRemoval($identity, $application, $factor, $factors),
            FailureReason::LAST_FACTOR,
            'The factor is the last one keeping a required factor covered.',
        );

        return $factor;
    }

    /**
     * Refuse the removal unless the session is fresh for removing a factor,
     * and, while the identity has another confirmed factor, fresh on proofs
     * made without the one being removed.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertFresh(MultiFactorAuthenticatable $identity, string $application, EloquentFactor&Model $factor, Collection $factors): void
    {
        $operation    = Operation::REMOVE_FACTOR->value;
        $requirements = $this->container->make(RequirementService::class);
        $id           = LockedFactors::idOf($factor);

        OperationRefusedException::unless($requirements->isFresh($operation), FailureReason::NOT_FRESH, 'Removing a factor needs a fresh step-up.');

        if (!$factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $id && $other->isConfirmed())) {
            return;
        }

        $requirement = $requirements->freshnessRequirement($operation);

        OperationRefusedException::unless($requirement !== null, FailureReason::NOT_FRESH, 'Removing a factor has no freshness to judge it by.');

        $proofs = array_filter(
            $this->container->make(SessionFirstFactor::class)->proofs($identity, $application),
            static fn (Proof $proof): bool => $proof->reference !== $id,
        );

        OperationRefusedException::unless(
            $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement(),
            FailureReason::NOT_FRESH,
            'Removing a factor needs a fresh step-up made with another factor.',
        );
    }
}
