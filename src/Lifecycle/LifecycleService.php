<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
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
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     */
    public function __construct(

        /** The container the event dispatcher is read from. */
        private Container $container,

        /** The proofs the removed factor made, which stop counting. */
        private ProofService $proofs,

        /** The recovery codes removed with the identity's last confirmed factor. */
        private RecoveryCodeService $recoveryCodes,

        /** The passkey associations removed with their factor. */
        private PasskeyAssociations $associations,
    ) {}

    /**
     * Disable a previously-enrolled factor for the current identity.
     *
     * Deletes the underlying row when the factor is an Eloquent model. An
     * `EloquentFactor` is deleted as stored, in the identity's factor state
     * transaction, and with it its passkey association and the identity's
     * recovery codes when no confirmed factor remains (a pending one does not
     * count; one disabled at the failure ceiling does); any other model is
     * deleted on its own. Then stops counting
     * every proof made with the factor on the current session, and dispatches
     * `MfaFactorDisabled`. Non-Eloquent factors are left for the consumer to
     * discard, with the recovery codes; their proofs stop counting and the
     * event still fires.
     *
     * Throws `FactorOwnershipMismatchException` when the factor does not belong
     * to the current identity, and `WriteCancelledException` when a model event
     * cancels the deletion, which then removes, forgets and reports nothing.
     * No-op when no MFA-capable person is signed in, and on a pending session
     * (see `Context\CallerContextResolver`).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     * @throws \Throwable
     */
    public function disable(Factor $factor): void
    {
        $identity = $this->container->make(CallerContextResolver::class)->resolve(null)?->identity;

        if ($identity === null) {
            return;
        }

        FactorOwnership::assert($factor, $identity);

        if (LockedFactors::keepsState($factor)) {
            $this->remove($identity, $factor);
        } elseif ($factor instanceof Model) {
            self::delete($factor);
        }

        $identifier = $factor->getFactorIdentifier();

        if (is_string($identifier) || is_int($identifier)) {
            $this->proofs->forgetFactor($identity, (string) $identifier);
        }

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaFactorDisabled($identity, $factor, $factor->getType()));
    }

    /**
     * Delete the factor as stored under the identity's lock, in its factor
     * state transaction, with its passkey association, and the identity's
     * recovery codes with it when none of the factors left under the lock is
     * confirmed. A factor already gone is not deleted again; the caller's
     * instance is marked as no longer stored.
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

            $stored  = LockedFactors::find($factor, $factors);
            $removed = LockedFactors::idOf($factor);

            if ($stored !== null) {
                self::delete($stored);
            }

            if ($removed !== null) {
                $this->associations->forget($removed);
            }

            $factor->exists = false;
            $remains        = $factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $removed && $other->isConfirmed());

            if ($remains) {
                return;
            }

            $this->recoveryCodes->removeSet($identity);
        });
    }

    /**
     * Delete the factor's row, and throw when a model event cancels the
     * deletion, so nothing is removed, forgotten or reported for a factor that
     * stays.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     */
    private static function delete(Model $factor): void
    {
        if ($factor->delete() === false) {
            throw new WriteCancelledException('A model event cancelled the factor\'s deletion, so it was not disabled.');
        }
    }
}
