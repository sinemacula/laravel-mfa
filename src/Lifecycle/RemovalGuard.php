<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\FactorChanges;

/**
 * What every removal of a factor checks, whichever entry point it comes
 * through, on the identity's factor state as the caller holds it:
 *
 * 1. the identity is active (`identity_inactive`);
 * 2. the factor is the identity's and was enrolled through the application
 *    acting, since an application never deletes a factor enrolled through
 *    another (`not_found`);
 * 3. it is confirmed; a pending one is cancelled or expires (`not_confirmed`);
 * 4. under the lock, the bound `Contracts\FactorChangeGate` authorises the
 *    removal from the session's sign-in (`mfa.remove_factor`): by default, the
 *    session is fresh for removing a factor, and while the identity has another
 *    confirmed factor, fresh on proofs made without this one, so a step-up with
 *    the factor being removed never authorises its own removal (`not_fresh`). A
 *    person whose other factor cannot be proved is reset by
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
     * Without a sign-in the bound factor change gate is not asked: that is the
     * check made before the lock, which the one under it repeats with it.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  ?string  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function assertRemovable(
        MultiFactorAuthenticatable $identity,
        string $application,
        (EloquentFactor&Model)|null $factor,
        Collection $factors,
        ?string $session = null,
    ): EloquentFactor&Model {
        OperationRefusedException::unless($this->container->make(ActiveStateResolver::class)->isActive($identity), FailureReason::IDENTITY_INACTIVE, 'The identity is inactive.');

        if ($factor === null || $factor->getApplication() !== $application) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The identity has no factor with that id enrolled through this application.');
        }

        OperationRefusedException::unless($factor->isConfirmed(), FailureReason::NOT_CONFIRMED, 'The factor is pending, so it is cancelled or expires instead.');

        if ($session !== null) {
            $this->container->make(FactorChanges::class)->allow($identity, $application, $session, FactorChange::REMOVE_FACTOR, $factors, LockedFactors::idOf($factor));
        }

        OperationRefusedException::unless(
            $this->container->make(LastFactorPolicy::class)->allowsRemoval($identity, $application, $factor, $factors),
            FailureReason::LAST_FACTOR,
            'The factor is the last one keeping a required factor covered.',
        );

        return $factor;
    }
}
