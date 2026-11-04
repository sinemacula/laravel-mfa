<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\FactorChanges;

/**
 * Whether a caller may add a factor of a type now, asked under the identity's
 * factor state lock with its factors as stored there, and how long that answer
 * lasts.
 *
 * On an active session the application must enable the type, and the bound
 * `Contracts\FactorChangeGate` must authorise the change from the session's
 * sign-in: an identity with a confirmed factor adding a further one
 * (`mfa.add_factor`), by default on a fresh step-up, and one with none
 * enrolling its first additional factor (`mfa.add_first_additional_factor`), by
 * default on its first factor proved again through the bound `Reauthenticator`.
 * The grant lasts as long as the authorisation. A pending session is exempt
 * only on the bootstrap path, which lasts as long as it does: its credential
 * allows the action, the application enables bootstrap for the type, and the
 * identity has no confirmed factor. Then the application's limits apply to the
 * factors enrolled through it: confirmed ones of the type, and confirmed ones
 * in all.
 *
 * Confirming an enrolment asks `reconfirm()` under the lock instead: the limits
 * again, and what the grant's authority rested on. Freshness is not judged
 * again, since a later proof must not stand in for the one that authorised the
 * grant: its lifetime already ends with that one.
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
     * Refuse unless the caller may add a factor of the type on the application
     * now, and say what authorised it and until when.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return \SineMacula\Laravel\Mfa\Enrollment\GrantAuthority
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function authorize(
        Caller $caller,
        string $application,
        string $type,
        Collection $factors,
        PendingAction $action = PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT,
    ): GrantAuthority {
        $settings = new ApplicationSettings($this->config, $application);
        $none     = self::confirmedOf($factors)->isEmpty();

        $authority = $caller->pending !== null
            ? self::authorizeBootstrap($caller->pending, $settings, $type, $none, $action)
            : $this->authorizeActive($caller, $settings, $application, $type, $factors, $none);

        $this->assertLimits($application, $type, $factors);

        return $authority;
    }

    /**
     * Refuse a factor beyond the application's limits on confirmed factors
     * enrolled through it, of the type and in all, and refuse a grant whose
     * authority no longer holds: a bootstrap grant while bootstrap no longer
     * allows the type or the identity has a confirmed factor, and a
     * reauthentication grant while it has one.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization  $authority
     * @param  string  $application
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function reconfirm(EnrollmentAuthorization $authority, string $application, string $type, Collection $factors): void
    {
        $this->assertLimits($application, $type, $factors);

        $none = self::confirmedOf($factors)->isEmpty();

        if ($authority === EnrollmentAuthorization::BOOTSTRAP) {
            self::assertBootstrap(new ApplicationSettings($this->config, $application), $type, $none);
        }

        OperationRefusedException::unless(
            $authority === EnrollmentAuthorization::STEP_UP || $none,
            FailureReason::NOT_FRESH,
            'The identity has a confirmed factor now, so this grant no longer authorises one.',
        );
    }

    /**
     * Refuse a factor beyond the application's limits on confirmed factors
     * enrolled through it: of the type, and in all.
     *
     * @formatter:off
     *
     * @param  string  $application
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function assertLimits(string $application, string $type, Collection $factors): void
    {
        $settings = new ApplicationSettings($this->config, $application);
        $enrolled = self::confirmedOf($factors)->filter(static fn (EloquentFactor&Model $factor): bool => $factor->getApplication() === $application);
        $ofType   = $enrolled->filter(static fn (EloquentFactor&Model $factor): bool => $factor->getType() === $type);
        $detail   = sprintf('The identity has as many factors enrolled through the application as it allows, of type [%s] or in all.', $type);

        OperationRefusedException::unless(
            $enrolled->count() < $settings->confirmedLimit() && $ofType->count() < $settings->confirmedPerTypeLimit(),
            FailureReason::LIMIT_REACHED,
            $detail,
        );
    }

    /**
     * The confirmed factors among those given.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @formatter:on
     */
    private static function confirmedOf(Collection $factors): Collection
    {
        return $factors->filter(static fn (EloquentFactor&Model $factor): bool => $factor->isConfirmed());
    }

    /**
     * Refuse a pending session unless it is on the bootstrap path for the type;
     * the grant lasts as long as the pending session does.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $settings
     * @param  string  $type
     * @param  bool  $none
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return \SineMacula\Laravel\Mfa\Enrollment\GrantAuthority
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function authorizeBootstrap(PendingContext $pending, ApplicationSettings $settings, string $type, bool $none, PendingAction $action): GrantAuthority
    {
        OperationRefusedException::unless(
            $pending->allows($action),
            FailureReason::NOT_FRESH,
            'The pending session may not do this with a bootstrap enrolment.',
        );

        self::assertBootstrap($settings, $type, $none);

        return new GrantAuthority(EnrollmentAuthorization::BOOTSTRAP, $pending->expiresAt);
    }

    /**
     * Refuse an identity with a confirmed factor, which must verify rather than
     * enrol whatever the application allows, then unless the application allows
     * bootstrap for the type.
     *
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $settings
     * @param  string  $type
     * @param  bool  $none
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function assertBootstrap(ApplicationSettings $settings, string $type, bool $none): void
    {
        OperationRefusedException::unless($none, FailureReason::NOT_FRESH, 'The identity has a confirmed factor, so the pending session must verify it.');

        OperationRefusedException::unless(
            $settings->allowsBootstrap(),
            FailureReason::MFA_ENROLLMENT_REQUIRED,
            'The application does not allow a pending session to enrol its first factor.',
        );

        OperationRefusedException::unless(
            in_array($type, $settings->bootstrapTypes(), true),
            FailureReason::TYPE_NOT_ENABLED,
            sprintf('The application does not allow bootstrap enrolment of [%s].', $type),
        );
    }

    /**
     * Refuse an active session a type the application does not enable, then
     * authorise it through the bound factor change gate: as the identity's
     * first additional factor, resting on its first factor proved again, or as
     * a further one, resting on a step-up. The grant lasts as long as the
     * gate's authorisation.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Applications\ApplicationSettings  $settings
     * @param  string  $application
     * @param  string  $type
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  bool  $none
     * @return \SineMacula\Laravel\Mfa\Enrollment\GrantAuthority
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function authorizeActive(Caller $caller, ApplicationSettings $settings, string $application, string $type, Collection $factors, bool $none): GrantAuthority
    {
        OperationRefusedException::unless($settings->enables($type), FailureReason::TYPE_NOT_ENABLED, sprintf('The application does not enable the type [%s].', $type));

        $session = $this->callers->binding($caller, $none ? Purpose::REAUTHENTICATE : Purpose::STEP_UP)?->sessionId;

        OperationRefusedException::unless($session !== null, FailureReason::NOT_FRESH, 'Adding a factor needs a sign-in to authorise it from.');

        $change = $none ? FactorChange::ADD_FIRST_ADDITIONAL_FACTOR : FactorChange::ADD_FACTOR;
        $until  = $this->container->make(FactorChanges::class)->grant($caller->identity, $application, $session, $change, $factors);

        return new GrantAuthority($none ? EnrollmentAuthorization::REAUTHENTICATION : EnrollmentAuthorization::STEP_UP, $until);
    }
}
