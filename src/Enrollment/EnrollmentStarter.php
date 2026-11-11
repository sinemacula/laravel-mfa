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
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
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
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * Starts an enrolment under the identity's factor lock, replacing any pending
 * factor of the same type for the application. The first code is sent inside
 * the transaction, so a failed delivery or a send cap leaves nothing behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentStarter
{
    /**
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

        /** Resolves seams. */
        private Container $container,

        /** Configuration. */
        private Repository $config,

        /** Caller resolver. */
        private CallerContextResolver $callers,

        /** Factor operation guard. */
        private OperationGuard $guard,

        /** IP throttle and identity lockout. */
        private AttemptService $attempts,

        /** Enrolment authorisation. */
        private EnrollmentAuthority $authority,

        /** Enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** Event dispatcher. */
        private EventDispatcher $events,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Throwable
     */
    public function start(CallerContext $context, #[\SensitiveParameter] EnrollmentRequest $request): EnrollmentStart
    {
        $caller  = $this->callers->resolve($context, PendingAction::START_BOOTSTRAP_ENROLLMENT);
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
                $caller->client->ip,
                function () use ($binding, $caller, $request, $driver, $destination, &$started): AttemptOutcome {

                    $started = FactorStateTransaction::forIdentity(
                        $caller->identity,
                        $this->factorModel(),
                        function (Collection $factors) use ($caller, $binding, $request, $driver, $destination): EnrollmentStart {

                            $current = $this->callers->still($caller, PendingAction::START_BOOTSTRAP_ENROLLMENT, $binding)
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

        $context = $this->events->context($identity, $application, $caller->client, $binding->sessionId);

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
            $this->sendFirstCode($caller, $factor, $binding, $row, $summary, $context);
        }

        return EnrollmentStart::started($summary, $grant, $expiresAt, $secret, $this->provisioningUri($driver, $factor, $request, $secret));
    }

    /**
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
     * A missing account name is a caller bug, so it throws rather than refuses.
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
     * The earlier of the configured lifetime and the authority's deadline.
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
     * Applies on a pending session, and on an active one only to the first
     * additional factor, so someone signed in by phone code cannot enrol that
     * same phone and be left with nothing else to offer.
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

        $firstFactor = $this->container->make(SessionFirstFactor::class)->forBinding($caller->identity, $binding, $caller->pending);

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
     * Discard this type's pending factor from any session, and expired ones.
     * Other applications' are left for pruning.
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

        $factor->setAttribute($relation->getMorphType(), IdentityType::of($caller->identity));
        $factor->setAttribute($relation->getForeignKeyName(), $binding->identityKey);
        $factor->setAttribute($factor->getTypeName(), $request->type);
        $factor->setAttribute($factor->getLabelName(), $request->label);
        $factor->setAttribute($factor->getDestinationName(), $destination);
        $factor->setAttribute($factor->getApplicationName(), $binding->application);

        return $factor;
    }

    /**
     * A code that does not go rolls the whole start back.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
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
    private function sendFirstCode(Caller $caller, EloquentFactor&Model $factor, ProofBinding $binding, Enrollment $row, FactorSummary $summary, array $context): void
    {
        $result      = $this->container->make(ChallengeGateway::class)->send($caller->context(), $factor, $binding);
        $challengeId = $result->challengeId ?? throw new CodeNotSentException($result);

        $this->enrollments->recordChallenge($row, $challengeId);

        $this->events->dispatch(new CodeSent($context, $summary, Purpose::ENROLLMENT, $challengeId));
    }

    /**
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
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function factorModel(): EloquentFactor&Model
    {
        return new (ConfiguredModels::factor($this->config));
    }

    /**
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
