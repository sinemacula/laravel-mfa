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
 * The checks every factor removal makes, whatever its entry point. By default a
 * step-up with the factor being removed never authorises its own removal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RemovalGuard
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * Without a session the factor change gate is skipped: that is the check
     * before the lock, which the one under it repeats with the session.
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
