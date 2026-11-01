<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Removes the current identity's factors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofService  $proofs
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     */
    public function __construct(

        /** The container the event dispatcher is read from. */
        private Container $container,

        /** The proofs the removed factor made, which stop counting. */
        private ProofService $proofs,

        /** The recovery codes removed with the identity's last confirmed factor. */
        private RecoveryCodeService $recoveryCodes,
    ) {}

    /**
     * Disable a previously-enrolled factor for the current identity.
     *
     * Deletes the underlying row when the factor is an Eloquent model, in the
     * identity's factor state transaction, and with it the identity's recovery
     * codes when no confirmed factor remains (a pending one does not count; one
     * disabled at the failure ceiling does). Then stops counting every proof
     * made with the factor on the current session, and dispatches
     * `MfaFactorDisabled`. Non-Eloquent factors are left for the consumer to
     * discard, with the recovery codes; their proofs stop counting and the
     * event still fires.
     *
     * Throws `FactorOwnershipMismatchException` when the factor does not belong
     * to the current identity. No-op when no MFA-capable identity is
     * resolvable.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     * @throws \Throwable
     */
    public function disable(Factor $factor): void
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return;
        }

        FactorOwnership::assert($factor, $identity);

        if (LockedFactors::keepsState($factor)) {
            $this->remove($identity, $factor);
        }

        $identifier = $factor->getFactorIdentifier();

        if (is_string($identifier) || is_int($identifier)) {
            $this->proofs->forgetFactor($identity, (string) $identifier);
        }

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaFactorDisabled($identity, $factor, $factor->getType()));
    }

    /**
     * Delete the factor in the identity's factor state transaction, and the
     * identity's recovery codes with it when none of the factors left under the
     * lock is confirmed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function remove(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor): void
    {
        FactorStateTransaction::forIdentity($identity, $factor, function (Collection $factors) use ($identity, $factor): void {

            $removed = LockedFactors::idOf($factor);

            $factor->delete();

            $remains = $factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $removed && $other->isConfirmed());

            if ($remains) {
                return;
            }

            $this->recoveryCodes->removeSet($identity);
        });
    }
}
