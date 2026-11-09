<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\SessionJudgement;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;

/**
 * Removes one of an identity's factors as one serialised change, inside the
 * identity's factor state transaction, once `RemovalGuard` has allowed it under
 * the same lock. Every entry point shares it, so an application's own removal
 * and a passkey's gate behave alike.
 *
 * In order: the factor and its passkey association are deleted; every proof
 * made with it stops counting, the current session's at once; with the last
 * confirmed factor the recovery code set goes; the identity's other sessions
 * are revoked through the bound `SessionRevoker`, told the factor and the
 * sign-in the removal is made from; the current session's requirement is
 * evaluated again on the proofs it still holds, and the removal goes to the
 * bound `SessionTransition` with any shortfall, unless the revoker judged the
 * session again itself; with that security work done `FactorRemoved` is queued,
 * then the recovery code set's removal is reported after it. So every package
 * row has changed before a session seam runs, in the lock order every change
 * shares, and the default revoker's kept proofs are recorded again before any
 * listener runs.
 *
 * A failure rolls the caller's whole change back. The proofs already forgotten
 * on the current session stay forgotten, which leaves it to verify again; they
 * are never restored, as that could undo a later invalidation. Nothing is
 * promoted when the preferred factor goes: that is the person's choice to make.
 *
 * `erase()` is what a reset does for each factor, with none of the rest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorRemoval
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofService  $proofs
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams are resolved from on every call. */
        private Container $container,

        /** The passkey association records. */
        private PasskeyAssociations $associations,

        /** The recovery codes removed with the last confirmed factor. */
        private RecoveryCodeService $recoveryCodes,

        /** The proofs the removed factor made, which stop counting. */
        private ProofService $proofs,

        /** The dispatcher of the removal's event. */
        private EventDispatcher $events,
    ) {}

    /**
     * Remove the factor, as stored under the identity's lock, from the
     * identity, acting on the application from the sign-in, and say how it
     * ended: with the requirement the session no longer meets, if any, and what
     * the bound revoker, or else the bound transition, returned for the caller.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  string  $session
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     * @throws \Throwable
     */
    public function remove(
        MultiFactorAuthenticatable $identity,
        string $application,
        EloquentFactor&Model $factor,
        Collection $factors,
        string $session,
        ?ClientContext $client = null,
    ): FactorRemovalResult {
        OpenTransaction::assertOpen('A factor is removed only inside the identity\'s factor state transaction.');

        $id      = self::idOf($factor);
        $summary = FactorSummary::fromFactor($factor);
        $context = $this->events->context($identity, $application, $client, $session);

        $this->erase($identity, $factor);

        $setRemoved = !$factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $id && $other->isConfirmed())
            && $this->recoveryCodes->deleteSet($identity);

        // What the current session still holds is read before the revocation,
        // which hides every proof it does not record again once committed.
        $kept = $this->container->make(SessionFirstFactor::class)->proofsOf($identity, $application, $session);

        $revocation   = $this->container->make(SessionRevoker::class)->factorRemoved($identity, $id, $application, $session);
        $reevaluation = $this->container->make(SessionReevaluation::class);

        $judgement = $revocation->judgedCurrent
            ? new SessionJudgement($reevaluation->outstanding($identity, $application, $kept), $revocation->completion())
            : $reevaluation->judge($identity, $application, $session, FactorChangeMade::REMOVED, $summary, $kept);

        $this->events->dispatch(new FactorRemoved($context, $summary));

        if ($setRemoved) {
            $this->recoveryCodes->reportSetRemoved($identity, null, $application, $client, $session);
        }

        return FactorRemovalResult::made($summary, $judgement->outstanding, $judgement->completion());
    }

    /**
     * Delete the factor and its passkey association, and stop every proof made
     * with it counting.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function erase(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor): void
    {
        $id = self::idOf($factor);

        $this->associations->forget($id);

        if ($factor->delete() === false) {
            throw new WriteCanceledException('A model event cancelled the factor\'s deletion, so it was not removed.');
        }

        $this->proofs->forgetFactor($identity, $id);
    }

    /**
     * The factor's id, which a factor is removed by.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    private static function idOf(EloquentFactor&Model $factor): string
    {
        return LockedFactors::idOf($factor) ?? throw new UnsupportedFactorException('A factor is removed by its id.');
    }
}
