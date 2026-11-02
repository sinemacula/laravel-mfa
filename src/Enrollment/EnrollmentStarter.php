<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Attempts\RequestIp;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProvisioningDriver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EnrollmentStarted;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Exceptions\SignInChangedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Starts an enrolment: a pending factor, a grant that may confirm it, and by
 * type a secret and its provisioning URI or a first code to the destination.
 *
 * The caller and its binding are captured; the identity, the type and the
 * destination are refused or normalised; an IP address slot is taken; then
 * under the identity's factor state lock the caller is resolved again, so a
 * sign-in that changed starts nothing. Under the lock the identity's lockout
 * and what authorises the enrolment are read (see `EnrollmentAuthority`), and
 * the grant's expiry is fixed once, as the earlier of the configured lifetime
 * and the end of that authority. The enrolment restarts: any pending factor of
 * the type through this application is discarded, from any session, with its
 * secret, and expired ones through this application with it. The pending limit
 * is then counted, the factor and its row are stored, and the first code goes
 * out inside the transaction, so a delivery that throws or a sending cap leaves
 * nothing.
 *
 * A code already delivered cannot be recalled: a later failure of the
 * transaction leaves one that matches nothing that can be confirmed, and
 * nothing retries it. The events wait for the commit, and the secrets are
 * returned only from one.
 *
 * Stateless: the seams and the configuration are read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentStarter
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority  $authority
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams are resolved from. */
        private Container $container,

        /** The configuration the applications and models are read from. */
        private Repository $config,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The guard every operation on a factor starts with. */
        private OperationGuard $guard,

        /** The throttle on the address and the identity's lockout. */
        private AttemptService $attempts,

        /** Whether the caller may add the factor now. */
        private EnrollmentAuthority $authority,

        /** The enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** The dispatcher of the enrolment's events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Start an enrolment for the person the request serves.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Throwable
     */
    public function start(#[\SensitiveParameter] EnrollmentRequest $request): EnrollmentStart
    {
        $caller  = $this->callers->resolve(PendingAction::START_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return EnrollmentStart::refused(FailureReason::NOT_FOUND);
        }

        try {
            $this->guard->identity($caller->identity);

            $driver = $this->driverFor($request, $binding->application);

            self::assertAccountName($request, $driver);

            $destination = self::destinationFor($request, $driver);
        } catch (OperationRefusedException $exception) {
            return EnrollmentStart::refused($exception->reason);
        }

        return $this->attempt($caller, $binding, $request, $driver, $destination);
    }

    /**
     * Start the enrolment holding a slot of the IP address's window and the
     * identity's lock, and answer a refusal made there, which rolled back all
     * it did.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  ?string  $destination
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Throwable
     */
    private function attempt(
        Caller $caller,
        ProofBinding $binding,
        #[\SensitiveParameter] EnrollmentRequest $request,
        FactorDriver $driver,
        #[\SensitiveParameter] ?string $destination,
    ): EnrollmentStart {
        $started = EnrollmentStart::refused(FailureReason::NOT_FOUND);

        try {
            $outcome = $this->attempts->throttled(
                RequestIp::resolve($this->container),
                function () use ($binding, $caller, $request, $driver, $destination, &$started): AttemptOutcome {

                    $started = FactorStateTransaction::forIdentity(
                        $caller->identity,
                        $this->factorModel(),
                        function (Collection $factors) use ($binding, $request, $driver, $destination): EnrollmentStart {

                            $current = $this->callers->still(PendingAction::START_BOOTSTRAP_ENROLLMENT, $binding)
                                ?? throw new SignInChangedException('The sign-in changed before the identity\'s lock was held.');

                            return $this->underLock($current, $binding, $request, $driver, $destination, $factors);
                        },
                    );

                    return AttemptOutcome::uncounted();
                },
            );
        } catch (CodeNotSentException|RefusedUnderLockException|SignInChangedException $exception) {
            return self::refusalOf($exception);
        }

        return $outcome->lockout === null ? $started : EnrollmentStart::refused(FailureReason::LOCKED, lockedUntil: $outcome->lockout->until);
    }

    /**
     * What a refusal carried out of the transaction answers.
     *
     * @param  \RuntimeException  $refusal
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     */
    private static function refusalOf(\RuntimeException $refusal): EnrollmentStart
    {
        return match (true) {
            $refusal instanceof CodeNotSentException      => EnrollmentStart::refused($refusal->result->reason ?? FailureReason::NOT_FOUND, $refusal->result->retryAfter),
            $refusal instanceof RefusedUnderLockException => EnrollmentStart::refused($refusal->refusal->reason),
            default                                       => EnrollmentStart::refused(FailureReason::NOT_FOUND),
        };
    }

    /**
     * Under the lock, for the caller as it stands now: refuse the enrolment or
     * make it.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  ?string  $destination
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function underLock(
        Caller $caller,
        ProofBinding $binding,
        #[\SensitiveParameter] EnrollmentRequest $request,
        FactorDriver $driver,
        #[\SensitiveParameter] ?string $destination,
        Collection $factors,
    ): EnrollmentStart {
        return RefusedUnderLockException::carrying(function () use ($caller, $binding, $request, $driver, $destination, $factors): EnrollmentStart {

            $lockout = $this->attempts->lockedOut($caller->identity, null);

            return $lockout === null
                ? $this->make($caller, $binding, $request, $driver, $destination, $factors)
                : EnrollmentStart::refused(FailureReason::LOCKED, lockedUntil: $lockout->until);
        });
    }

    /**
     * Authorise the enrolment, discard what it replaces, count the limit, store
     * the factor and its row, send the first code, and queue the events.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  ?string  $destination
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function make(
        Caller $caller,
        ProofBinding $binding,
        #[\SensitiveParameter] EnrollmentRequest $request,
        FactorDriver $driver,
        #[\SensitiveParameter] ?string $destination,
        Collection $factors,
    ): EnrollmentStart {
        $identity    = $caller->identity;
        $application = $binding->application;
        $authority   = $this->authority->authorize($caller, $application, $request->type, $factors, PendingAction::START_BOOTSTRAP_ENROLLMENT);
        $expiresAt   = $this->expiry($authority->deadline);

        $this->assertCombination($caller, $binding, $driver, $destination, $factors);

        $context = $this->events->context($identity, $application);

        $this->discard($identity, $binding, $request->type, $factors, $context);
        $this->assertPendingLimit($binding);

        $factor = $this->newFactor($caller, $binding, $request, $destination);
        $secret = $driver->startEnrollment($factor);

        $factor->setAttribute($factor->getSecretName(), $secret?->reveal());
        $factor->persist();

        $id      = self::storedId($factor);
        $grant   = EnrollmentGrant::issue();
        $current = VerificationGeneration::current($identity);
        $row     = $this->enrollments->create($id, EnrollmentGrant::hash($grant), $binding, $current, $authority->kind, $expiresAt);
        $summary = FactorSummary::fromFactor($factor);

        $this->events->dispatch(new EnrollmentStarted($context, $summary));

        if ($driver instanceof CodeDeliveryDriver) {
            $this->sendFirstCode($factor, $binding, $row, $summary, $context);
        }

        return EnrollmentStart::started($summary, $grant, $expiresAt, $secret, $this->provisioningUri($driver, $factor, $request, $secret));
    }

    /**
     * The driver of the type, refusing a type the application does not enable,
     * a passkey, which enrols only through its registration, and a type whose
     * channel can carry no factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function driverFor(#[\SensitiveParameter] EnrollmentRequest $request, string $application): FactorDriver
    {
        $type = $request->type;

        OperationRefusedException::unless(
            (new ApplicationSettings($this->config, $application))->enables($type),
            FailureReason::TYPE_NOT_ENABLED,
            sprintf('The application does not enable the type [%s].', $type),
        );

        OperationRefusedException::unless($type !== PasskeyAssertions::TYPE, FailureReason::NOT_ACCEPTED, 'A passkey enrols only from its registration.');

        $driver = $this->container->make(DriverResolver::class)->fromContainer($this->container, $type);

        OperationRefusedException::unless($driver->channelKind()->carriesFactor(), FailureReason::NOT_ACCEPTED, 'The type travels on no channel a factor can.');

        return $driver;
    }

    /**
     * Refuse a type that provisions an authenticator app without the account
     * name it shows, a mistake of the caller's rather than a person's.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertAccountName(#[\SensitiveParameter] EnrollmentRequest $request, FactorDriver $driver): void
    {
        if ($driver instanceof ProvisioningDriver && $request->accountName === null) {
            throw new \InvalidArgumentException(sprintf('Enrolling the type [%s] needs the account name its authenticator app shows.', $request->type));
        }
    }

    /**
     * The destination a delivered type captures, normalised, refusing one the
     * type cannot deliver to, or none; other types have none.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function destinationFor(#[\SensitiveParameter] EnrollmentRequest $request, FactorDriver $driver): ?string
    {
        if (!$driver instanceof CodeDeliveryDriver) {
            return null;
        }

        $destination = $driver->normalizeDestination($request->destination() ?? '');

        OperationRefusedException::unless($destination !== null, FailureReason::INVALID_DESTINATION, 'The destination is not one the type can deliver to.');

        return $destination;
    }

    /**
     * The grant's expiry: the earlier of the configured lifetime and the end of
     * what authorised it, floored to the second as it is stored, and refused
     * when nothing of it is left.
     *
     * @param  \Carbon\CarbonImmutable  $deadline
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function expiry(CarbonImmutable $deadline): CarbonImmutable
    {
        $now      = CarbonImmutable::now();
        $lifetime = $now->addMinutes((new EnrollmentSettings($this->config))->ttlMinutes());
        $expiry   = $deadline->min($lifetime)->startOfSecond();

        OperationRefusedException::unless($expiry->greaterThan($now), FailureReason::NOT_FRESH, 'What authorised the enrolment has no time left.');

        return $expiry;
    }

    /**
     * Refuse a factor the combination policy would not accept after the
     * session's first factor, when it must be: always on a pending session, and
     * on an active one only for the identity's first additional factor while
     * that first factor is known. Someone signed in by phone code who enrols
     * that same phone would otherwise be short, with nothing to offer. A later
     * factor may serve another sign-in.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  ?string  $destination
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertCombination(Caller $caller, ProofBinding $binding, FactorDriver $driver, #[\SensitiveParameter] ?string $destination, Collection $factors): void
    {
        $active = $caller->pending === null;

        if ($active && $factors->contains(static fn (EloquentFactor&Model $factor): bool => $factor->isConfirmed())) {
            return;
        }

        $firstFactor = $this->container->make(SessionFirstFactor::class)->forBinding($caller->identity, $binding);

        if ($active && $firstFactor === null) {
            return;
        }

        $policy = $this->container->make(CombinationPolicy::class);

        OperationRefusedException::unless(
            $firstFactor !== null && $policy->accepts($firstFactor, FactorChannel::prospective($driver->channelKind(), $destination)),
            FailureReason::NOT_ACCEPTED,
            'The combination policy would not accept the factor after the session\'s first factor.',
        );
    }

    /**
     * Discard the pending factor of the type through the application, from any
     * session, and any no longer live through it. Another application's are
     * left for it, or for pruning.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  array<string, int|string|null>  $context
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private function discard(MultiFactorAuthenticatable $identity, ProofBinding $binding, string $type, Collection $factors, array $context): void
    {
        foreach ($this->enrollments->ofApplication(ProofOwner::boundBy($binding), $binding->application) as $enrollment) {

            $factor = $factors->first(static fn (EloquentFactor&Model $candidate): bool => LockedFactors::idOf($candidate) === $enrollment->factor_id);

            if ($factor === null) {
                $this->enrollments->forget($enrollment);

                continue;
            }

            $this->discardIfReplaced($identity, $enrollment, $factor, $type, $context);
        }
    }

    /**
     * Discard the enrolment when a new one of its type replaces it or it is no
     * longer live, reporting which.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $type
     * @param  array<string, int|string|null>  $context
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private function discardIfReplaced(MultiFactorAuthenticatable $identity, Enrollment $enrollment, EloquentFactor&Model $factor, string $type, array $context): void
    {
        $replaced = $factor->getType() === $type;

        if (!$replaced && $this->enrollments->isLive($enrollment, $identity)) {
            return;
        }

        $this->enrollments->discard($enrollment, $factor);

        $summary = FactorSummary::fromFactor($factor);

        $this->events->dispatch($replaced ? new EnrollmentAbandoned($context, $summary) : new EnrollmentExpired($context, $summary));
    }

    /**
     * Refuse a further pending factor past the application's limit on its live
     * ones, all that remain of it once the expired have been discarded.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertPendingLimit(ProofBinding $binding): void
    {
        $live  = $this->enrollments->ofApplication(ProofOwner::boundBy($binding), $binding->application)->count();
        $limit = (new ApplicationSettings($this->config, $binding->application))->pendingLimit();

        OperationRefusedException::unless($live < $limit, FailureReason::LIMIT_REACHED, 'The identity has as many enrolments in progress through the application as it allows.');
    }

    /**
     * A new pending factor of the request's type, of the caller's, enrolled
     * through the binding's application, with the destination captured.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  ?string  $destination
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function newFactor(
        Caller $caller,
        ProofBinding $binding,
        #[\SensitiveParameter] EnrollmentRequest $request,
        #[\SensitiveParameter] ?string $destination,
    ): EloquentFactor&Model {
        $factor   = $this->factorModel();
        $relation = $factor->authenticatable();

        $factor->setAttribute($relation->getMorphType(), CurrentIdentity::typeOf($caller->identity));
        $factor->setAttribute($relation->getForeignKeyName(), $binding->identityKey);
        $factor->setAttribute($factor->getTypeName(), $request->type);
        $factor->setAttribute($factor->getLabelName(), $request->label);
        $factor->setAttribute($factor->getDestinationName(), $destination);
        $factor->setAttribute($factor->getApplicationName(), $binding->application);

        return $factor;
    }

    /**
     * Send the pending factor's first code, recording its challenge once it has
     * gone; one that does not go rolls the whole start back.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $row
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $summary
     * @param  array<string, int|string|null>  $context
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException
     */
    private function sendFirstCode(EloquentFactor&Model $factor, ProofBinding $binding, Enrollment $row, FactorSummary $summary, array $context): void
    {
        $challengeId = self::challengeOf($this->container->make(ChallengeGateway::class)->send($factor, $binding));

        $this->enrollments->recordChallenge($row, $challengeId);

        $this->events->dispatch(new CodeSent($context, $summary, Purpose::ENROLLMENT, $challengeId));
    }

    /**
     * The challenge a code went out under, refusing a send that made none.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\SendResult  $result
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException
     */
    private static function challengeOf(SendResult $result): string
    {
        return $result->challengeId ?? throw new CodeNotSentException($result);
    }

    /**
     * The URI an authenticator app reads the secret from, for a type that
     * provisions one, under the request's issuer or the configured one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @param  ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $secret
     * @return ?\SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     *
     * @throws \InvalidArgumentException
     */
    private function provisioningUri(
        FactorDriver $driver,
        EloquentFactor&Model $factor,
        #[\SensitiveParameter] EnrollmentRequest $request,
        #[\SensitiveParameter] ?RevealedSecret $secret,
    ): ?RevealedSecret {
        if (!$driver instanceof ProvisioningDriver || $secret === null) {
            return null;
        }

        return $driver->provisioningUri($factor, $request->issuer ?? (new TotpSettings($this->config))->issuer(), (string) $request->accountName, $secret);
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
        return new (ConfiguredModels::factor($this->config));
    }

    /**
     * The stored factor's id, throwing when a model event cancelled its save.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private static function storedId(EloquentFactor&Model $factor): string
    {
        $id = $factor->exists ? LockedFactors::idOf($factor) : null;

        return $id ?? throw new WriteCanceledException('A model event cancelled the pending factor\'s save, so its enrolment did not start.');
    }
}
