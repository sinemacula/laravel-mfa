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
 * Removes a factor inside the identity's factor state transaction. Every row
 * changes before a session seam runs, and events go out only after.
 *
 * Proofs forgotten on the current session stay forgotten on rollback, since
 * restoring them could undo a later invalidation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorRemoval
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofService  $proofs
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,

        /** Passkey association records. */
        private PasskeyAssociations $associations,

        /** Removed with the last confirmed factor. */
        private RecoveryCodeService $recoveryCodes,

        /** Proofs made with the factor stop counting. */
        private ProofService $proofs,

        /** Dispatches the removal's event. */
        private EventDispatcher $events,
    ) {}

    /**
     * The factor must be as stored under the identity's lock.
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

        // Read first: the revocation hides proofs it does not record again.
        // A store may list the removed factor's proofs until they are voided.
        $kept = [];

        foreach ($this->container->make(SessionFirstFactor::class)->proofsOf($identity, $application, $session) as $proof) {
            if ($proof->reference === $id) {
                continue;
            }

            $kept[] = $proof;
        }

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
     * What a reset does for each factor, without the session work.
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
