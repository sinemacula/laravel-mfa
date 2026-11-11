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
 * Whether a caller may add a factor of a type, asked under the identity's
 * factor lock. An active session goes through `Contracts\FactorChangeGate`; a
 * pending session only through bootstrap. Refusals throw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentAuthority
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** Resolves seams on every call. */
        private Container $container,

        /** Read on every call. */
        private Repository $config,

        /** Caller resolver. */
        private CallerContextResolver $callers,
    ) {}

    /**
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
     * Recheck at confirmation. Freshness is not judged again, so a later proof
     * cannot stand in for the one that authorised the grant.
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

        $session = $this->callers->binding($caller, Purpose::STEP_UP)?->sessionId;

        OperationRefusedException::unless($session !== null, FailureReason::NOT_FRESH, 'Adding a factor needs a sign-in to authorise it from.');

        $change = $none ? FactorChange::ADD_FIRST_ADDITIONAL_FACTOR : FactorChange::ADD_FACTOR;
        $until  = $this->container->make(FactorChanges::class)->grant($caller->identity, $application, $session, $change, $factors);

        return new GrantAuthority($none ? EnrollmentAuthorization::REAUTHENTICATION : EnrollmentAuthorization::STEP_UP, $until);
    }
}
