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
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\OperationRequirements;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * The gate every entry point that registers, removes or changes a passkey calls
 * before it does, the authentication layer's included, in the same change: an
 * event reporting the change afterwards cannot stand in for it.
 *
 * Each call runs inside the caller's own transaction on the storage connection
 * and refuses with a `LogicException` without one. It acts only for the
 * request's validated caller, the identity and application it names, under the
 * identity's factor state lock, which joins the caller's transaction and is
 * held until it commits. A refusal is an `OperationRefusedException` carrying
 * the reason, so the caller's registration or change rolls back with it; a
 * caller that catches the refusal and commits anyway breaks the contract. Every
 * event waits for the caller's commit, so a caller that rolls back after an
 * allowed call leaves no factor, association or event behind.
 *
 * - `registering()` associates a passkey with the identity as a factor when the
 *   application enables the type, confirmed by the registration ceremony's own
 *   evidence, with the fresh step-up, reauthentication or bootstrap exemption
 *   and the limits an enrolment needs, and recovery codes with the first
 *   additional factor. A credential associated already, with this identity or
 *   another, is refused.
 * - `removing()` removes the factor an associated credential is, with the fresh
 *   step-up a removal needs (proved without that factor while another remains),
 *   the last factor policy, and the revocation of the identity's other
 *   sessions.
 * - `changing()` refuses any change to an associated credential: one to what it
 *   proves is a removal and then a registration. A label, its counter and its
 *   last use are not gated.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  ?string  $label
     * @return ?\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function registering(MultiFactorAuthenticatable $identity, string $application, PasskeyRegistration $registration, ?string $label = null): ?PasskeyAssociationResult
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        if (!$this->settings($application)->enables(PasskeyAssertions::TYPE) || !$this->container->make(SubjectTypeResolver::class)->isPerson($identity)) {
            return null;
        }

        $caller = $this->caller($identity, $application, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT);

        $this->assertRegistration($caller, $registration);

        return FactorStateTransaction::forIdentity(
            $identity,
            $this->factorModel(),
            fn (Collection $factors): PasskeyAssociationResult => $this->associate($caller, $application, $registration, $label, $factors),
        );
    }

    /**
     * Remove the factor the credential is associated as, before the caller
     * removes the credential; nothing when it is associated with nobody.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function removing(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): void
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        $credentialId = CredentialId::canonical($credentialId);

        // A plain read: the association is locked, and looked up again, only
        // once the identity's factor state lock is held, in that order.
        if (!$this->associations->exists($credentialId)) {
            return;
        }

        $this->caller($identity, $application, null);

        FactorStateTransaction::forIdentity($identity, $this->factorModel(), function (Collection $factors) use ($identity, $application, $credentialId): void {
            $this->remove($identity, $application, $credentialId, $factors);
        });
    }

    /**
     * Refuse a change to an associated credential before the caller makes it;
     * nothing when the credential is associated with nobody.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function changing(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): void
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        if (!$this->associations->exists(CredentialId::canonical($credentialId))) {
            return;
        }

        $this->caller($identity, $application, null);

        self::refuseChange();
    }

    /**
     * Under the lock: refuse an inactive identity, a credential associated
     * already and an enrolment the caller may not make now, then store the
     * confirmed factor and its association, and recovery codes with the
     * identity's first additional factor.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  ?string  $label
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     * @throws \Throwable
     */
    private function associate(Caller $caller, string $application, PasskeyRegistration $registration, ?string $label, Collection $factors): PasskeyAssociationResult
    {
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
        $context = $this->events->context($identity, $application);

        $this->associations->associate(ProofOwner::of($identity), $id, $registration->credentialId);

        $this->events->dispatch(new PasskeyAssociated($context, $summary));
        $this->events->dispatch(new FactorConfirmed($context, $summary));

        $codes = $first && $this->issuesRecoveryCodes($identity, $application, $registration, $id)
            ? $this->container->make(RecoveryCodeService::class)->generate($identity, null, $application)
            : [];

        return new PasskeyAssociationResult($summary, $codes);
    }

    /**
     * Under the lock: remove the identity's factor the credential is associated
     * as, once the session is fresh enough to; an association no factor of the
     * identity's remains for is deleted on its own.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function remove(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId, Collection $factors): void
    {
        $association = $this->associations->forCredential($credentialId);

        if ($association === null) {
            return;
        }

        $owner = ProofOwner::of($identity);

        OperationRefusedException::unless(
            $association->authenticatable_type === $owner->type && $association->authenticatable_id === $owner->key,
            FailureReason::NOT_FOUND,
            'The credential is associated with another identity.',
        );

        $factor = $factors->first(static fn (EloquentFactor&Model $candidate): bool => LockedFactors::idOf($candidate) === $association->factor_id);

        if ($factor === null) {
            $this->associations->forget($association->factor_id);

            return;
        }

        $this->assertFreshForRemoval($identity, $application, $association->factor_id, $factors);

        $this->container->make(FactorRemoval::class)->remove($identity, $application, $factor, $factors);
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
     * @param  string  $factorId
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertFreshForRemoval(MultiFactorAuthenticatable $identity, string $application, string $factorId, Collection $factors): void
    {
        $operation = Operation::REMOVE_FACTOR->value;

        OperationRefusedException::unless(
            $this->container->make(RequirementService::class)->isFresh($operation),
            FailureReason::NOT_FRESH,
            'Removing a factor needs a fresh step-up.',
        );

        if (!$factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $factorId && $other->isConfirmed())) {
            return;
        }

        $requirement = (new OperationRequirements($this->config))->effective($application, $operation);

        OperationRefusedException::unless($requirement !== null, FailureReason::NOT_FRESH, 'Removing a factor has no freshness configured to judge it by.');

        $proofs = array_values(array_filter(
            $this->container->make(SessionFirstFactor::class)->proofs($identity, $application),
            static fn (Proof $proof): bool => $proof->reference !== $factorId,
        ));
        $fresh = $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement();

        OperationRefusedException::unless($fresh, FailureReason::NOT_FRESH, 'Removing a factor needs a fresh step-up made with another factor.');
    }

    /**
     * Whether recovery codes come with the identity's first additional factor:
     * the application accepts them, and the session's first factor followed by
     * the registration's own evidence meets the level the application issues
     * them at.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  string  $factorId
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function issuesRecoveryCodes(MultiFactorAuthenticatable $identity, string $application, PasskeyRegistration $registration, string $factorId): bool
    {
        $settings    = $this->settings($application);
        $firstFactor = $this->container->make(SessionFirstFactor::class)->forBinding($identity, $registration->binding);

        if (!$settings->acceptsRecoveryCodes() || $firstFactor === null) {
            return false;
        }

        $proof = new Proof(
            kind      : ProofKind::ADDITIONAL_FACTOR,
            method    : PasskeyAssertions::TYPE,
            channel   : new Channel(ChannelKind::PASSKEY, $registration->credentialId),
            reference : $factorId,
            properties: $registration->properties,
            provedAt  : CarbonImmutable::now(),
            binding   : $registration->binding,
            generation: VerificationGeneration::current($identity),
        );

        $requirement = Requirement::none()->withMinimumLevel($settings->recoveryCodeLevel());

        return $this->container->make(RequirementCheck::class)->check($requirement, $firstFactor, $proof)->meetsRequirement();
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

        $factor->setAttribute($relation->getMorphType(), CurrentIdentity::typeOf($identity));
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
     * The request's validated caller, refused unless it is the identity and the
     * application given.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return \SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function caller(MultiFactorAuthenticatable $identity, string $application, ?PendingAction $action): Caller
    {
        $caller   = $this->callers->resolve($action);
        $isCaller = $caller !== null && ProofOwner::of($caller->identity)->slot() === ProofOwner::of($identity)->slot() && $this->callers->application($caller) === $application;

        OperationRefusedException::unless($isCaller, FailureReason::NOT_FOUND, 'The identity and application are not the request\'s validated caller.');

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
     * Refuse a change to an associated credential: a change to what it proves
     * is a removal and then a registration.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refuseChange(): never
    {
        throw new OperationRefusedException(FailureReason::CREDENTIAL_ASSOCIATED, 'An associated credential is not changed in place: remove it, then register the new one.');
    }

    /**
     * The stored factor's id, throwing when a model event cancelled its save,
     * so the passkey is not associated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     */
    private static function storedId(EloquentFactor&Model $factor): string
    {
        $id = $factor->exists ? LockedFactors::idOf($factor) : null;

        return $id ?? throw new WriteCancelledException('A model event cancelled the passkey factor\'s save, so the passkey was not associated.');
    }
}
