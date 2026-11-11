<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enrollment\GrantAuthority;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Factors\FactorSets;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Requirements\ScriptedFactorChangeGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(GrantAuthority::class)]
final class EnrollmentAuthorityTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * The reauthentication must be of the current sign-in and under five
     * minutes old.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFirstFactorNeedsAFreshReauthentication(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now());

        $this->enablePasskeys();

        $user  = $this->signedInPerson();
        $store = $this->container()->make(ProofStore::class);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user, null, 'web'), 'passkey'));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, 0, 'another-sign-in'));

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user, null, 'web'), 'passkey'));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE + 1));

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user, null, 'web'), 'passkey'));

        // Exactly five minutes old would grant nothing that lasts.
        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE));

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user, null, 'web'), 'passkey'));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store, ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE - 1));

        self::assertNull($this->refusal(new Caller($user, null, 'web'), 'passkey'));

        CarbonImmutable::setTestNow();
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutASignInTheReauthenticatorIsNotAsked(): void
    {
        $this->enablePasskeys();

        $user            = $this->signedInPerson();
        $reauthenticator = new FreshReauthenticator($this->container()->make(ProofStore::class));

        $this->container()->instance(Reauthenticator::class, $reauthenticator);
        $this->container()->make(ProofStore::class)->forget($user, self::APPLICATION);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user, null, 'web'), 'passkey'));
        self::assertSame(0, $reauthenticator->asked);
    }

    /**
     * Its credential must allow it, the application allow bootstrap for the
     * type, and the identity hold no confirmed factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPendingSessionNeedsTheBootstrapPath(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal($this->pending($user, [PendingAction::VERIFY]), 'passkey'));
        self::assertSame(FailureReason::MFA_ENROLLMENT_REQUIRED, $this->refusal($this->pending($user), 'passkey'));

        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['totp']]]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->refusal($this->pending($user), 'passkey'));
        self::assertNull($this->refusal($this->pending($user), 'totp'));

        $this->confirmedFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal($this->pending($user), 'totp'));
    }

    /**
     * Even where bootstrap is off, since it has nothing to enrol to get
     * through.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAConfirmedFactorIsReportedBeforeBootstrapBeingOff(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        $this->confirmedFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal($this->pending($user), 'totp'));
    }

    /**
     * An active session may add only a type the application enables.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachPathSaysWhatAuthorizedItAndUntilWhen(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['totp']]]);

        $user = $this->signedInPerson();

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($this->container()->make(ProofStore::class), 60));

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->refusal(new Caller($user, null, 'web'), 'sms'));

        $first = $this->authorized(new Caller($user, null, 'web'), 'totp');

        self::assertSame(EnrollmentAuthorization::REAUTHENTICATION, $first->kind);
        self::assertTrue(CarbonImmutable::now()->addSeconds(240)->equalTo($first->deadline));

        $pending = $this->pending($user);
        $boot    = $this->authorized($pending, 'totp');

        self::assertSame(EnrollmentAuthorization::BOOTSTRAP, $boot->kind);
        self::assertSame($pending->pending?->expiresAt, $boot->deadline);

        $this->stepUpWith($user, $this->confirmedFactor($user));

        self::assertSame(EnrollmentAuthorization::STEP_UP, $this->authorized(new Caller($user, null, 'web'), 'passkey')->kind);

        CarbonImmutable::setTestNow();
    }

    /**
     * A first or a further factor from the session's sign-in, lasting as long
     * as the gate's authorisation; a bootstrap enrolment never asks it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionsEnrolmentIsTheBoundGatesToAuthorize(): void
    {
        $this->enablePasskeys(['bootstrap' => ['enabled' => true, 'types' => ['totp']]]);

        $until = CarbonImmutable::now()->addMinutes(3);
        $gate  = new ScriptedFactorChangeGate($until);
        $user  = $this->signedInPerson();

        $this->container()->instance(FactorChangeGate::class, $gate);

        $first = $this->authorized(new Caller($user, null, 'web'), 'totp');

        self::assertSame(EnrollmentAuthorization::REAUTHENTICATION, $first->kind);
        self::assertSame($until, $first->deadline);

        $this->authorized($this->pending($user), 'totp');
        $this->confirmedFactor($user);

        self::assertSame(EnrollmentAuthorization::STEP_UP, $this->authorized(new Caller($user, null, 'web'), 'passkey')->kind);
        self::assertSame([FactorChange::ADD_FIRST_ADDITIONAL_FACTOR, FactorChange::ADD_FACTOR], array_map(static fn ($request): FactorChange => $request->change, $gate->requests));
        self::assertSame([self::SESSION, self::SESSION], array_map(static fn ($request): string => $request->session, $gate->requests));

        $refusal = new OperationRefusedException(FailureReason::LAST_FACTOR, 'The layer says no.');

        $this->container()->instance(FactorChangeGate::class, new ScriptedFactorChangeGate(refusal: $refusal));

        self::assertSame(FailureReason::LAST_FACTOR, $this->refusal(new Caller($user, null, 'web'), 'passkey'));
    }

    /**
     * Refused without the gate being asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionWithNoSignInIsNotFresh(): void
    {
        $this->enablePasskeys();

        $gate = new ScriptedFactorChangeGate(CarbonImmutable::now()->addMinutes(3));
        $user = $this->signedInPerson();

        $this->container()->instance(FactorChangeGate::class, $gate);
        $this->container()->make(ProofStore::class)->forget($user, self::APPLICATION);

        self::assertSame(FailureReason::NOT_FRESH, $this->refusal(new Caller($user, null, 'web'), 'totp'));
        self::assertSame([], $gate->requests);
    }

    /**
     * The limits, and no confirmed factor for what having none authorised.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReconfirmingAsksWhatTheGrantRestedOn(): void
    {
        $this->enablePasskeys(['limits' => ['confirmed' => 1], 'bootstrap' => ['enabled' => true, 'types' => ['totp']]]);

        $user = $this->signedInPerson();

        self::assertNull($this->reconfirmed(EnrollmentAuthorization::STEP_UP));
        self::assertNull($this->reconfirmed(EnrollmentAuthorization::REAUTHENTICATION));
        self::assertNull($this->reconfirmed(EnrollmentAuthorization::BOOTSTRAP));

        $factor = $this->confirmedFactor($user);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->reconfirmed(EnrollmentAuthorization::STEP_UP));

        $factor->update(['application' => 'admin']);

        self::assertNull($this->reconfirmed(EnrollmentAuthorization::STEP_UP));
        self::assertSame(FailureReason::NOT_FRESH, $this->reconfirmed(EnrollmentAuthorization::REAUTHENTICATION));
        self::assertSame(FailureReason::NOT_FRESH, $this->reconfirmed(EnrollmentAuthorization::BOOTSTRAP));
    }

    /**
     * Factors enrolled elsewhere do not count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLimitsApplyToFactorsEnrolledThroughTheApplication(): void
    {
        $this->enablePasskeys(['types' => ['totp', 'passkey', 'sms'], 'limits' => ['confirmed' => 2, 'confirmed_per_type' => 1]]);

        $user = $this->signedInPerson();
        $totp = $this->confirmedFactor($user);

        $this->stepUpWith($user, $totp);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->refusal(new Caller($user, null, 'web'), 'totp'));
        self::assertNull($this->refusal(new Caller($user, null, 'web'), 'passkey'));

        $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->refusal(new Caller($user, null, 'web'), 'sms'));

        Factor::query()->update(['application' => 'admin']);

        self::assertNull($this->refusal(new Caller($user, null, 'web'), 'totp'));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function authority(): EnrollmentAuthority
    {
        return $this->container()->make(EnrollmentAuthority::class);
    }

    /**
     * Why a grant of the kind is refused on the factors stored now, or `null`.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization  $kind
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function reconfirmed(EnrollmentAuthorization $kind): ?FailureReason
    {
        try {
            $this->authority()->reconfirm($kind, self::APPLICATION, 'totp', FactorSets::stored());
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        return null;
    }

    /**
     * Allowing the actions given, or the bootstrap confirmation by default.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return \SineMacula\Laravel\Mfa\Context\Caller
     */
    private function pending(TestUser $user, array $actions = [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]): Caller
    {
        $first = SignInProofs::of($user)->inSession('pending-1')->password();

        $pending = new PendingContext($user, self::APPLICATION, 'pending-1', $first, Requirement::none(), $actions, CarbonImmutable::now()->addMinutes(10));

        return new Caller($user, $pending, self::APPLICATION);
    }

    /**
     * Runs inside a transaction, as the factor state lock does.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Enrollment\GrantAuthority
     *
     * @throws \Throwable
     */
    private function authorized(Caller $caller, string $type): GrantAuthority
    {
        return DB::transaction(fn (): GrantAuthority => $this->container()->make(EnrollmentAuthority::class)->authorize($caller, self::APPLICATION, $type, FactorSets::stored()));
    }

    /**
     * Why the caller is refused a factor of the type, or `null`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function refusal(Caller $caller, string $type): ?FailureReason
    {
        try {
            $this->authorized($caller, $type);
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        return null;
    }
}
