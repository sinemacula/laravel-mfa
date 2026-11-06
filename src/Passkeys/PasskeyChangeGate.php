<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\BootstrapEnrollmentCompleted;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\RemovalGuard;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Support\IdentityType;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;

/**
 * The gate every entry point that registers or removes a passkey calls before
 * it does, the authentication layer's included, in the same change: an event
 * reporting the change afterwards cannot stand in for it.
 *
 * Each call runs inside the caller's own transaction on the storage connection
 * and refuses with a `LogicException` without one. It acts only for the
 * request's validated caller, the identity and application it names, under the
 * identity's factor state lock, which joins the caller's transaction and is
 * held until it commits. A refusal is an `OperationRefusedException` carrying
 * the reason, so the caller's registration or removal rolls back with it; a
 * caller that catches the refusal and commits anyway breaks the contract. Every
 * event waits for the caller's commit, so a caller that rolls back after an
 * allowed call leaves no factor, association or event behind.
 *
 * - `registering()` associates a passkey with the identity as a factor when the
 *   application enables the type, confirmed by the registration ceremony's own
 *   evidence, with the fresh step-up, reauthentication or bootstrap exemption
 *   and the limits an enrolment needs, and recovery codes with the first
 *   additional factor. A confirmed factor ends a re-enrolment obligation. On a
 *   pending session its proof goes to the bound `PendingCompletion`; on an
 *   active one the requirement is evaluated again on the proofs the session
 *   holds, and the registration goes to the bound `SessionTransition` with any
 *   shortfall, whose answer the result carries; a refusal of either rolls the
 *   registration back. A credential associated already, with this identity or
 *   another, is refused.
 * - `removing()` removes the factor an associated credential is, on a sign-in
 *   the proof store knows (`not_fresh` without one), compared again under the
 *   lock (`not_found` when it changed), with the checks of every removal (see
 *   `Lifecycle\RemovalGuard`): an active identity; enrolled through the
 *   application acting, so another application's is refused as `not_found` and
 *   the caller's removal of the credential rolls back with it; the fresh
 *   step-up a removal needs (proved without that factor while another remains);
 *   and the last factor policy. Then the identity's other sessions are revoked.
 *
 * Stateless: the request, the configuration and the seams are read on every
 * call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PasskeyChangeGate
{
    /** @var string Why a call made outside a transaction is refused. */
    private const string NO_TRANSACTION = 'The passkey change gate runs only inside the caller\'s transaction on the storage connection.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams and the services are resolved from. */
        private Container $container,

        /** The configuration the applications and models are read from. */
        private Repository $config,

        /** The resolver of the validated caller. */
        private CallerContextResolver $callers,

        /** The association records. */
        private PasskeyAssociations $associations,

        /** The dispatcher of the association's events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Associate the passkey being registered with the identity as a factor,
     * before the caller stores it, and return the factor and any recovery
     * codes; `null` when the application does not enable passkeys or the
     * identity is not a person, so the registration goes on as a sign-in
     * passkey only.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  ?string  $label
     * @return ?\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function registering(CallerContext $caller, PasskeyRegistration $registration, ?string $label = null): ?PasskeyAssociationResult
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        $identity    = $caller->identity;
        $application = $caller->application;

        if ($identity === null || !$this->settings($application)->enables(PasskeyAssertions::TYPE) || !$this->container->make(SubjectTypeResolver::class)->isPerson($identity)) {
            return null;
        }

        $served = $this->caller($caller, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT);

        $this->assertRegistration($served, $registration);

        return FactorStateTransaction::forIdentity(
            $identity,
            $this->factorModel(),
            fn (Collection $factors): PasskeyAssociationResult => $this->associate($served, $application, $registration, $label, $factors),
        );
    }

    /**
     * Remove the factor the credential is associated as, before the caller
     * removes the credential; nothing when it is associated with nobody.
     * Returns what the bound `SessionRevoker` returned for the caller, such as
     * an authentication layer's result carrying the pending session's new
     * credential, or `null` with nothing to return.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $credentialId
     * @return ?object
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function removing(CallerContext $caller, #[\SensitiveParameter] string $credentialId): ?object
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        $credentialId = CredentialId::canonical($credentialId);

        // A plain read: the association is locked, and looked up again, only
        // once the identity's factor state lock is held, in that order.
        if (!$this->associations->exists($credentialId)) {
            return null;
        }

        $served      = $this->caller($caller, null);
        $identity    = $served->identity;
        $application = $served->application;
        $binding     = $this->callers->binding($served, Purpose::STEP_UP);

        // No sign-in means nothing a step-up could have been made on, or to
        // compare under the lock, whatever a bound gate would answer.
        if ($binding === null) {
            throw new OperationRefusedException(FailureReason::NOT_FRESH, 'Removing a factor needs a sign-in the proof store knows of.');
        }

        return FactorStateTransaction::forIdentity(
            $identity,
            $this->factorModel(),
            fn (Collection $factors): ?object => $this->remove($served, $binding, $application, $credentialId, $factors),
        );
    }

    /**
     * Under the lock: refuse a sign-in that changed, an inactive identity, a
     * credential associated already and an enrolment the caller may not make
     * now, then store the confirmed factor and its association, end any
     * re-enrolment obligation, issue recovery codes with the identity's first
     * additional factor, and hand a pending session's proof over or evaluate an
     * active session's requirement again.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  ?string  $label
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     * @throws \Throwable
     */
    private function associate(Caller $served, string $application, PasskeyRegistration $registration, ?string $label, Collection $factors): PasskeyAssociationResult
    {
        $caller = $this->callers->still($served, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT, $registration->binding);

        if ($caller === null) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The sign-in the registration was made on is no longer the caller\'s.');
        }

        $identity = $caller->identity;

        $this->container->make(OperationGuard::class)->identity($identity);

        // Without a lock: the unique credential index refuses an association a
        // concurrent registration commits after this read.
        OperationRefusedException::unless(
            !$this->associations->exists($registration->credentialId),
            FailureReason::CREDENTIAL_ASSOCIATED,
            'The credential is associated as a factor already.',
        );

        $this->container->make(EnrollmentAuthority::class)->authorize($caller, $application, PasskeyAssertions::TYPE, $factors);

        $first   = !$factors->contains(static fn (EloquentFactor&Model $factor): bool => $factor->isConfirmed());
        $factor  = $this->store($identity, $application, $registration->credentialId, $label);
        $id      = self::storedId($factor);
        $summary = FactorSummary::fromFactor($factor);
        $context = $this->events->context($identity, $application, $caller->client);
        $proof   = self::proofOf($identity, $registration, $id);

        $this->associations->associate(ProofOwner::of($identity), $id, $registration->credentialId);

        $this->events->dispatch(new PasskeyAssociated($context, $summary));
        $this->events->dispatch(new FactorConfirmed($context, $summary));

        if ($caller->pending !== null) {
            $this->events->dispatch(new BootstrapEnrollmentCompleted($context, $summary));
        }

        ReenrollmentObligation::end($identity);

        $acceptance = $this->container->make(ProofAcceptance::class);
        $result     = $caller->pending === null ? null : $acceptance->evaluate($caller, $proof, [], PasskeyAssertions::TYPE);
        $codes      = $first ? $this->container->make(RecoveryCodeIssuance::class)->withFirstFactor($identity, $application, $proof, $caller->pending, $caller->client) : [];

        if ($result !== null) {
            return new PasskeyAssociationResult($summary, $codes, $result->withCompletion($acceptance->handOver($caller, $result)));
        }

        $proofs    = $this->container->make(SessionFirstFactor::class)->proofs($identity, $application);
        $judgement = $this->container->make(SessionReevaluation::class)
            ->judge($identity, $application, $registration->binding->sessionId, FactorChangeMade::PASSKEY_REGISTERED, $summary, $proofs);

        return new PasskeyAssociationResult($summary, $codes, completion: $judgement->completion());
    }

    /**
     * Under the lock: resolve the caller again, refusing a sign-in that
     * changed, then remove the identity's factor the credential is associated
     * as, once every check of a removal holds; an association no factor of the
     * identity's remains for is deleted on its own.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $application
     * @param  string  $credentialId
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return ?object
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function remove(Caller $served, ProofBinding $binding, string $application, #[\SensitiveParameter] string $credentialId, Collection $factors): ?object
    {
        $caller = $this->callers->still($served, null, $binding);

        if ($caller === null) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The sign-in changed before the identity\'s lock was held.');
        }

        $identity    = $caller->identity;
        $association = $this->associations->ownedCredential($credentialId, ProofOwner::of($identity));

        if ($association === null) {

            // The locking query names the owner, so another identity's
            // association is not returned or acted on: only this unlocked read
            // tells it apart from a credential nobody holds.
            OperationRefusedException::unless(
                !$this->associations->exists($credentialId),
                FailureReason::NOT_FOUND,
                'The credential is associated with another identity.',
            );

            return null;
        }

        $factor = $factors->first(static fn (EloquentFactor&Model $candidate): bool => LockedFactors::idOf($candidate) === $association->factor_id);

        if ($factor === null) {
            $this->associations->forget($association->factor_id);

            return null;
        }

        $this->container->make(RemovalGuard::class)->assertRemovable($identity, $application, $factor, $factors, $binding->sessionId);

        return $this->container->make(FactorRemoval::class)->remove($identity, $application, $factor, $factors, $binding->sessionId, $caller->client)->completion();
    }

    /**
     * Store the passkey factor, confirmed, enrolled through the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @param  ?string  $label
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function store(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId, ?string $label): EloquentFactor&Model
    {
        $factor   = $this->factorModel();
        $relation = $factor->authenticatable();

        $factor->setAttribute($relation->getMorphType(), IdentityType::of($identity));
        $factor->setAttribute($relation->getForeignKeyName(), ProofOwner::of($identity)->key);
        $factor->setAttribute($factor->getTypeName(), PasskeyAssertions::TYPE);
        $factor->setAttribute($factor->getLabelName(), $label);
        $factor->setAttribute($factor->getCredentialReferenceName(), $credentialId);
        $factor->setAttribute($factor->getApplicationName(), $application);
        $factor->confirm();
        $factor->persist();

        return $factor;
    }

    /**
     * Refuse a registration bound to anything but the caller's own enrolment on
     * its session, or one that observed no user presence.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertRegistration(Caller $caller, PasskeyRegistration $registration): void
    {
        $binding = $this->callers->binding($caller, Purpose::ENROLLMENT);

        OperationRefusedException::unless(
            $binding?->toArray() === $registration->binding->toArray(),
            FailureReason::NOT_FOUND,
            'The registration is bound to another identity, application or session.',
        );

        OperationRefusedException::unless($registration->properties->userPresence === true, FailureReason::INVALID_CODE, 'The registration observed no user presence.');
    }

    /**
     * The caller served for the change, refused when it is nobody the change
     * serves.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  ?\SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return \SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function caller(CallerContext $context, ?PendingAction $action): Caller
    {
        $caller = $this->callers->resolve($context, $action);

        OperationRefusedException::unless($caller !== null, FailureReason::NOT_FOUND, 'The caller is not served for this change.');

        return $caller;
    }

    /**
     * The application's settings.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Applications\ApplicationSettings
     */
    private function settings(string $application): ApplicationSettings
    {
        return new ApplicationSettings($this->config, $application);
    }

    /**
     * A new instance of the configured factor model.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function factorModel(): EloquentFactor&Model
    {
        $model = ConfiguredModels::factor($this->config);

        return new $model;
    }

    /**
     * The proof a registration makes of the factor it stores: its own evidence,
     * bound to the enrolment.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  string  $factorId
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function proofOf(MultiFactorAuthenticatable $identity, PasskeyRegistration $registration, string $factorId): Proof
    {
        return new Proof(
            kind      : ProofKind::ADDITIONAL_FACTOR,
            method    : PasskeyAssertions::TYPE,
            channel   : new Channel(ChannelKind::PASSKEY, $registration->credentialId),
            reference : $factorId,
            properties: $registration->properties,
            provedAt  : CarbonImmutable::now(),
            binding   : $registration->binding,
            generation: VerificationGeneration::current($identity),
        );
    }

    /**
     * The stored factor's id, throwing when a model event cancelled its save,
     * so the passkey is not associated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private static function storedId(EloquentFactor&Model $factor): string
    {
        $id = $factor->exists ? LockedFactors::idOf($factor) : null;

        return $id ?? throw new WriteCanceledException('A model event cancelled the passkey factor\'s save, so the passkey was not associated.');
    }
}
