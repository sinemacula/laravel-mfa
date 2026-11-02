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
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;

/**
 * Removes one of an identity's factors as one serialised change, inside the
 * identity's factor state transaction, after the caller has checked that the
 * session is fresh enough to.
 *
 * In order: the bound `LastFactorPolicy` is asked again, under the lock; the
 * factor and its passkey association are deleted, and with the last confirmed
 * factor the recovery code set; every proof made with the factor stops
 * counting, the current session's at once; the identity's other sessions are
 * revoked through the bound `SessionRevoker`; the current session's
 * requirement is evaluated again on the proofs it still holds, and a shortfall
 * is handed to the bound `SessionTransition`; `FactorRemoved` is dispatched
 * once the change commits. A refusal throws, so the caller's whole change rolls
 * back; the proofs already forgotten on the current session stay forgotten,
 * which leaves it to verify again.
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
     * identity, acting on the application.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @return void
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     * @throws \Throwable
     */
    public function remove(MultiFactorAuthenticatable $identity, string $application, EloquentFactor&Model $factor, Collection $factors, ?Actor $actor = null): void
    {
        OpenTransaction::assertOpen('A factor is removed only inside the identity\'s factor state transaction.');

        if (!$this->container->make(LastFactorPolicy::class)->allowsRemoval($identity, $application, $factor)) {
            throw new OperationRefusedException(FailureReason::LAST_FACTOR, 'The factor is the last one keeping a required factor covered.');
        }

        $id      = LockedFactors::idOf($factor) ?? throw new UnsupportedFactorException('A factor is removed by its id.');
        $summary = FactorSummary::fromFactor($factor);

        $this->associations->forget($id);

        if ($factor->delete() === false) {
            throw new WriteCancelledException('A model event cancelled the factor\'s deletion, so it was not removed.');
        }

        if (!$factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $id && $other->isConfirmed())) {
            $this->recoveryCodes->removeSet($identity, $actor);
        }

        $this->proofs->forgetFactor($identity, $id);

        // What the current session still holds is read before the revocation,
        // which hides every proof it does not record again once committed.
        $kept = $this->container->make(SessionFirstFactor::class)->proofs($identity, $application);

        $this->container->make(SessionRevoker::class)->revokeOthers($identity);

        $this->reevaluate($identity, $application, $kept);

        $this->events->dispatch(new FactorRemoved($this->events->context($identity, $application), $summary, $actor));
    }

    /**
     * Evaluate the session's requirement again on the proofs it kept, and hand
     * a shortfall to the bound session transition.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $kept
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function reevaluate(MultiFactorAuthenticatable $identity, string $application, array $kept): void
    {
        $requirement = $this->container->make(RequirementService::class)->requirementFor($identity, $application);

        if ($this->container->make(RequirementCheck::class)->check($requirement, ...$kept)->meetsRequirement()) {
            return;
        }

        $this->container->make(SessionTransition::class)->returnToPending($identity, $application, $requirement);
    }
}
