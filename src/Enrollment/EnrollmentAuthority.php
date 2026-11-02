<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;

/**
 * Whether a caller may add a factor of a type now, asked under the identity's
 * factor state lock with its factors as stored there.
 *
 * On an active session, an identity with a confirmed factor needs a fresh
 * step-up for `mfa.add_factor` (see `Contracts\FreshnessGate`); one with none,
 * enrolling its first additional factor, needs its first factor proved again
 * through the bound `Reauthenticator`, which the default refuses: a first
 * factor reauthentication of the identity on the application, bound to its
 * current sign-in, made under its current verification generation within the
 * last five minutes. A pending session is exempt only on the bootstrap path:
 * its credential allows confirming a bootstrap enrolment, the application
 * enables bootstrap for the type, and the identity has no confirmed factor.
 * Then the application's limits apply to the factors enrolled through it:
 * confirmed ones of the type, and confirmed ones in all.
 *
 * A refusal throws an `OperationRefusedException` carrying the reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentAuthority
{
    /** @var int How old, in seconds, a reauthentication may be and still authorise a first additional factor. */
    public const int REAUTHENTICATION_MAX_AGE = 300;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** The container the seams are resolved from on every call. */
        private Container $container,

        /** The configuration the applications are read from on every call. */
        private Repository $config,

        /** The resolver of the caller's session. */
        private CallerContextResolver $callers,
    ) {}

    /**
     * Refuse unless the caller may add a factor of the type on the
     * application now.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function authorize(Caller $caller, string $application, string $type, Collection $factors): void
    {
        $settings  = new ApplicationSettings($this->config, $application);
        $confirmed = $factors->filter(static fn (EloquentFactor&Model $factor): bool => $factor->isConfirmed());

        if ($caller->pending !== null) {
            self::authorizeBootstrap($caller->pending, $settings, $type, $confirmed->isEmpty());
        } elseif ($confirmed->isEmpty()) {
            $this->authorizeReauthentication($caller, $application);
        } elseif (!$this->container->make(RequirementService::class)->isFresh(Operation::ADD_FACTOR->value)) {
            throw new OperationRefusedException(FailureReason::NOT_FRESH, 'Adding a factor needs a fresh step-up.');
        }

        self::assertLimits($settings, $application, $type, $confirmed);
    }

    /**
     * Refuse a pending session unless it is on the bootstrap path for the
     * type.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $settings
     * @param  string  $type
     * @param  bool  $none
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function authorizeBootstrap(PendingContext $pending, ApplicationSettings $settings, string $type, bool $none): void
    {
        [$reason, $detail] = match (true) {
            !$pending->allows(PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT) => [FailureReason::NOT_FRESH, 'The pending session may not confirm a bootstrap enrolment.'],
            !$settings->allowsBootstrap()                                  => [FailureReason::MFA_ENROLLMENT_REQUIRED, 'The application does not allow a pending session to enrol its first factor.'],
            !in_array($type, $settings->bootstrapTypes(), true)            => [FailureReason::TYPE_NOT_ENABLED, sprintf('The application does not allow bootstrap enrolment of [%s].', $type)],
            !$none                                                         => [FailureReason::NOT_FRESH, 'The identity has a confirmed factor, so the pending session must verify it.'],
            default                                                        => [null, ''],
        };

        if ($reason !== null) {
            throw new OperationRefusedException($reason, $detail);
        }
    }

    /**
     * Refuse an active session enrolling its first additional factor unless
     * the bound reauthenticator proves its first factor again, now.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function authorizeReauthentication(Caller $caller, string $application): void
    {
        $session = $this->callers->binding($caller, Purpose::REAUTHENTICATE)?->sessionId;
        $proof   = $session === null ? null : $this->container->make(Reauthenticator::class)->reauthenticate($caller->identity, $application);

        if ($proof === null || $session === null || !self::isFreshReauthentication($proof, $caller->identity, $application, $session)) {
            throw new OperationRefusedException(FailureReason::NOT_FRESH, 'Adding a first additional factor needs the first factor proved again.');
        }
    }

    /**
     * Whether the proof is a reauthentication with the identity's first factor
     * on its current sign-in, under its current verification generation, made
     * within the last five minutes and not after now.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isFreshReauthentication(Proof $proof, MultiFactorAuthenticatable $identity, string $application, string $session): bool
    {
        $now = CarbonImmutable::now();

        return $proof->kind === ProofKind::FIRST_FACTOR_REAUTHENTICATION
            && ProofOwner::of($identity)->ownsSignIn($proof->binding, $application, $session)
            && $proof->generation === VerificationGeneration::current($identity)
            && $proof->provedAt->lessThanOrEqualTo($now)
            && $proof->provedAt->greaterThanOrEqualTo($now->subSeconds(self::REAUTHENTICATION_MAX_AGE));
    }

    /**
     * Refuse a factor beyond the application's limits on confirmed factors
     * enrolled through it: of the type, and in all.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $settings
     * @param  string  $application
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $confirmed
     * @return void
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function assertLimits(ApplicationSettings $settings, string $application, string $type, Collection $confirmed): void
    {
        $enrolled = $confirmed->filter(static fn (EloquentFactor&Model $factor): bool => $factor->getApplication() === $application);
        $ofType   = $enrolled->filter(static fn (EloquentFactor&Model $factor): bool => $factor->getType() === $type);

        if ($enrolled->count() >= $settings->confirmedLimit() || $ofType->count() >= $settings->confirmedPerTypeLimit()) {
            throw new OperationRefusedException(FailureReason::LIMIT_REACHED, sprintf('The identity has as many factors enrolled through the application as it allows, of type [%s] or in all.', $type));
        }
    }
}
