<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Contracts\Factor as ContractFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentGrant;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enrollment\GrantAuthority;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Factors\UnwrittenFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FixedReauthenticator;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\TestCase;

/**
 * Every gate an enrolment passes before it starts: who is asking, the type, the
 * destination, the lockouts, what authorises it, the combination it would make,
 * and the limits; each refused with its reason, leaving nothing behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentService::class)]
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(GrantAuthority::class)]
#[CoversClass(EnrollmentGrant::class)]
#[CoversClass(EnrollmentRequest::class)]
#[CoversClass(EnrollmentStart::class)]
#[CoversClass(EnrollmentConfirmation::class)]
#[CoversClass(EnrollmentSettings::class)]
#[CoversClass(FactorChannel::class)]
#[CoversClass(FactorLabel::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(CodeNotSentException::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(SessionReevaluation::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(RequirementService::class)]
#[CoversClass(TotpDriver::class)]
#[CoversClass(TotpSettings::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(MfaManager::class)]
#[CoversClass(Evaluation::class)]
#[CoversClass(Combination::class)]
#[CoversClass(DefaultCombinationPolicy::class)]
final class GatesEnrollmentStarterTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * Nobody signed in, a machine, a person with no sign-in the store knows of,
     * and a pending credential that does not allow starting are all served
     * nothing.
     *
     * @return void
     */
    public function testARequestServingNobodyIsNotFound(): void
    {
        $request = EnrollmentRequest::totp(self::ACCOUNT);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->startEnrollment(Callers::current(), $request)->reason);

        $this->actingAs(new NonEloquentIdentity(person: false));

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->startEnrollment(Callers::current(), $request)->reason);

        $user = $this->person();

        $this->actingAs($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->startEnrollment(Callers::current(), $request)->reason);

        $this->pendingSession($user, null, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT, PendingAction::SEND_CODE]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->startEnrollment(Callers::current(), $request)->reason);
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * An inactive identity is refused.
     *
     * @return void
     */
    public function testAnInactiveIdentityIsRefused(): void
    {
        $identity = new NonEloquentIdentity(active: false);

        $this->actingAs($identity);

        $this->container()->make(ProofStore::class)->begin($identity, self::APPLICATION, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
    }

    /**
     * A type the application does not enable is refused, and a passkey, which
     * enrols only from its registration, before its driver is asked.
     *
     * @return void
     */
    public function testATypeThatMayNotStartIsRefused(): void
    {
        $this->enablePasskeys();
        $this->mfa()->extend('noop', fn (): NoopFactorDriver => new NoopFactorDriver);
        $this->enableApplication(['types' => ['email', 'passkey', 'noop']]);
        $this->steppedUpPerson();

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of('no_such_type'))->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of('passkey'))->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of('noop'))->reason);
        self::assertSame(1, Factor::query()->count());
    }

    /**
     * Rows of `[type, destination]` of destinations the type cannot deliver to.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function invalidDestinations(): iterable
    {
        yield 'an email address with no at' => ['email', 'person.example.test'];
        yield 'a blank email address' => ['email', '   '];
        yield 'a phone number with no plus' => ['sms', '447700900123'];
        yield 'a phone number with a leading zero' => ['sms', '+07700900123'];
        yield 'a phone number too short' => ['sms', '+1234567'];
        yield 'a phone number too long' => ['sms', '+1234567890123456'];
        yield 'a phone number with letters' => ['sms', '+44770090012a'];
        yield 'a phone number with a trailing line' => ['sms', "+447700900123\n"];
    }

    /**
     * A destination the type cannot deliver to is refused before anything is
     * stored or sent.
     *
     * @param  string  $type
     * @param  string  $destination
     * @return void
     */
    #[DataProvider('invalidDestinations')]
    public function testAnInvalidDestinationIsRefused(string $type, string $destination): void
    {
        FakeSmsSender::fake($this->container());

        $this->enableApplication(['types' => ['totp', 'email', 'sms']]);
        $this->steppedUpPerson();

        self::assertSame(FailureReason::INVALID_DESTINATION, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered($type, $destination))->reason);
        self::assertSame(1, Factor::query()->count());
    }

    /**
     * A delivered type with no destination is refused as one with a bad one.
     *
     * @return void
     */
    public function testADeliveredTypeWithNoDestinationIsRefused(): void
    {
        $this->steppedUpPerson();

        self::assertSame(FailureReason::INVALID_DESTINATION, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of('email'))->reason);
    }

    /**
     * A type that provisions an authenticator app needs the account name it
     * shows, which is the caller's mistake to make.
     *
     * @return void
     */
    public function testATypeThatProvisionsNeedsAnAccountName(): void
    {
        $this->steppedUpPerson();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Enrolling the type [totp] needs the account name its authenticator app shows.');

        $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of('totp'));
    }

    /**
     * The address's throttle refuses a start, counting nothing against it when
     * one goes ahead.
     *
     * @return void
     */
    public function testTheAddressThrottleRefusesAStart(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->steppedUpPerson();

        $first = $this->startedTotp();

        self::assertSame(0, $this->addressHits('127.0.0.1'));

        $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($first), $this->wrongCode($first));

        self::assertSame(1, $this->addressHits('127.0.0.1'));

        $start = $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));

        self::assertSame(FailureReason::LOCKED, $start->reason);
        self::assertNotNull($start->lockedUntil);
        self::assertTrue($this->rowOf($first)->exists);
    }

    /**
     * An identity's lockout refuses a start, with when it lifts.
     *
     * @return void
     */
    public function testALockedIdentityIsRefused(): void
    {
        $user  = $this->steppedUpPerson();
        $owner = ProofOwner::of($user);
        $until = CarbonImmutable::now()->addMinutes(5);

        IdentityState::query()->updateOrCreate(['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key], ['locked_until' => $until]);

        $start = $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));

        self::assertSame(FailureReason::LOCKED, $start->reason);
        self::assertSame($until->getTimestamp(), $start->lockedUntil?->getTimestamp());
        self::assertSame(1, Factor::query()->count());
    }

    /**
     * With a confirmed factor and no step-up, the session is not fresh.
     *
     * @return void
     */
    public function testAFactorWithNoStepUpIsNotFresh(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user, ['application' => self::APPLICATION]);
        $this->recordFirstFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
    }

    /**
     * With no factor, the default reauthenticator refuses, and so does any
     * proof that is not of the first factor made under the current generation.
     *
     * @return void
     */
    public function testAFirstFactorNeedsAReauthentication(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);

        $this->container()->instance(Reauthenticator::class, new FixedReauthenticator(SignInProofs::of($user)->inSession('other')->reauthentication()));

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);

        $this->container()->instance(Reauthenticator::class, new FixedReauthenticator(SignInProofs::of($user)->inSession(self::SESSION)->reauthentication(10)));

        $start = $this->startedTotp();

        self::assertSame(EnrollmentAuthorization::REAUTHENTICATION, $this->rowOf($start)->authority);
    }

    /**
     * A stored factor whose status is none the package knows is not read as
     * pending, which would let a first factor's reauthentication stand in for
     * the step-up a confirmed one needs: the start throws, and nothing is
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorWithAnUnknownStatusStopsTheStart(): void
    {
        $user   = $this->reauthenticatedPerson();
        $stored = $this->totpFactor($user, ['application' => self::APPLICATION]);

        Factor::query()->whereKey($stored->id)->toBase()->update(['status' => 'CONFIRMED']);

        try {
            $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));

            self::fail('An unknown status must not read as pending.');
        } catch (InvalidModelException $exception) {
            self::assertStringContainsString('[status]', $exception->getMessage());
        }

        self::assertSame([$stored->id], Factor::query()->pluck('id')->all());
        self::assertSame(0, Enrollment::query()->count());
    }

    /**
     * With a factor and a step-up the row records it as what authorised the
     * enrolment.
     *
     * @return void
     */
    public function testAStepUpIsRecordedAsTheAuthority(): void
    {
        $this->steppedUpPerson();

        self::assertSame(EnrollmentAuthorization::STEP_UP, $this->rowOf($this->startedTotp())->authority);
    }

    /**
     * Bootstrap is off by default, then each of its conditions refuses in turn.
     *
     * @return void
     */
    public function testBootstrapHasItsConditions(): void
    {
        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);

        self::assertSame(FailureReason::MFA_ENROLLMENT_REQUIRED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);

        $this->enableApplication(['bootstrap' => ['enabled' => true, 'types' => ['email']]]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);

        $start = $this->startedEmail();

        self::assertSame(EnrollmentAuthorization::BOOTSTRAP, $this->rowOf($start)->authority);

        $this->totpFactor($user);

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->reason);

        // Having a factor to verify, it is told to, whatever bootstrap allows.
        $this->enableApplication();

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
    }

    /**
     * An action other than the one asked for does not stand in for it: a direct
     * call of the authority on behalf of a credential lacking it refuses.
     *
     * @return void
     */
    public function testTheAuthorityAsksForTheActionNamed(): void
    {
        $user = $this->bootstrapPerson(actions: [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]);

        $pending = Callers::current()->pending;

        self::assertNotNull($pending);

        $authority = $this->container()->make(EnrollmentAuthority::class);

        try {
            $authority->authorize(new Caller($user, $pending, $pending->application), self::APPLICATION, 'totp', Factor::query()->get(), PendingAction::START_BOOTSTRAP_ENROLLMENT);

            self::fail('A credential lacking the action was expected to be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
        }
    }

    /**
     * On a bootstrap session the factor must be one the policy accepts after
     * the first factor, and a session whose first factor is not known accepts
     * none.
     *
     * @return void
     */
    public function testBootstrapRefusesACombinationThePolicyDoesNotAccept(): void
    {
        $user = $this->bootstrapPerson();

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS, firstFactor: $this->emailFirstFactor($user, self::PENDING));

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->reason);
        self::assertSame(0, Factor::query()->count());

        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', 'other@example.test'))->hasStarted());
        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->hasStarted());

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS, firstFactor: SignInProofs::of($user)->inSession(self::PENDING)->underGeneration(5)->password());

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
    }

    /**
     * On an active session the same combination is refused only for the
     * identity's first additional factor, and only while its first factor is
     * known; a later factor is useful on another sign-in.
     *
     * @return void
     */
    public function testAnActiveSessionRefusesACombinationOnlyForItsFirstFactor(): void
    {
        config()->set('mfa.codes.resend_cooldown_seconds', 0);

        $user  = $this->signedInPerson();
        $store = $this->container()->make(ProofStore::class);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        // No first factor known: it may not be judged.
        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(null));
        $this->enableApplication(['first_factor' => null]);

        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->hasStarted());

        Enrollment::query()->delete();
        Factor::query()->delete();

        $store->record($this->emailFirstFactor($user, self::SESSION));

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->reason);
        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', 'other@example.test'))->hasStarted());

        Enrollment::query()->delete();
        Factor::query()->delete();

        $factor = $this->totpFactor($user, ['application' => self::APPLICATION]);

        $this->recordStepUp($user, $factor);

        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->hasStarted());
    }

    /**
     * Limits on confirmed factors, per type and in all, count those enrolled
     * through this application only.
     *
     * @return void
     */
    public function testTheConfirmedLimitsCountThisApplicationsOnly(): void
    {
        $this->enableApplication(['limits' => ['confirmed' => 2, 'confirmed_per_type' => 1]]);

        $user = $this->steppedUpPerson();

        self::assertSame(FailureReason::LIMIT_REACHED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->hasStarted());

        $this->emailFactor($user, 'second@example.test', ['application' => self::APPLICATION]);

        self::assertSame(FailureReason::LIMIT_REACHED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS))->reason);

        Factor::query()->where('status', 'confirmed')->update(['application' => 'admin']);

        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->hasStarted());
    }

    /**
     * The limit on pending enrolments counts this application's live ones.
     *
     * @return void
     */
    public function testThePendingLimitCountsThisApplicationsLiveOnes(): void
    {
        $this->enableApplication(['limits' => ['pending' => 1]]);
        $this->steppedUpPerson();

        $first = $this->startedEmail();

        self::assertSame(FailureReason::LIMIT_REACHED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
        self::assertTrue($this->rowOf($first)->exists);

        Enrollment::query()->update(['application' => 'admin']);

        self::assertTrue($this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->hasStarted());
        self::assertSame(2, Enrollment::query()->count());
    }

    /**
     * A sign-in that changes between capture and lock starts nothing.
     *
     * @return void
     */
    public function testASignInChangedBeforeTheLockStartsNothing(): void
    {
        $this->steppedUpPerson();

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));
        $this->forgetReports();

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->reason);
        self::assertSame(0, Enrollment::query()->count());
        self::assertSame([], $this->reported);
    }

    /**
     * A model event that cancels the pending factor's save stops the start.
     *
     * @return void
     */
    public function testACanceledSaveStopsTheStart(): void
    {
        $this->steppedUpPerson();

        Factor::creating(static fn (): bool => false);

        $this->expectException(WriteCanceledException::class);

        $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));
    }

    /**
     * A persistence seam that neither writes the factor nor throws stops the
     * start all the same.
     *
     * @return void
     */
    public function testAFactorThatWasNotWrittenStopsTheStart(): void
    {
        $this->steppedUpPerson();

        config()->set('mfa.factor.model', UnwrittenFactor::class);

        $this->expectException(WriteCanceledException::class);
        $this->expectExceptionMessage('its enrolment did not start');

        $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));
    }

    /**
     * A disabled passkey is refused as a disabled type, not as a passkey.
     *
     * @return void
     */
    public function testADisabledPasskeyIsADisabledType(): void
    {
        $this->steppedUpPerson();

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of('passkey'))->reason);
    }

    /**
     * A driver of the application's own may keep a secret with no URI to read
     * it from, which is returned alone.
     *
     * @return void
     */
    public function testADriverMayKeepASecretWithNoUri(): void
    {
        $this->mfa()->extend('own', fn (): FactorDriver => new class implements FactorDriver {
            use DescribesNoChannel;

            /**
             * Travel as an authenticator app does.
             *
             * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
             */
            #[\Override]
            public function channelKind(): ChannelKind
            {
                return ChannelKind::AUTHENTICATOR_APP;
            }

            /**
             * Keep a fixed secret.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
             */
            #[\Override]
            public function startEnrollment(ContractFactor $factor): RevealedSecret
            {
                return new RevealedSecret('own-secret');
            }

            /**
             * Accept one code.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @param  string  $code
             * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
             * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
             */
            #[\Override]
            public function verify(ContractFactor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
            {
                return $code === 'correct' ? CodeCheck::ACCEPTED : CodeCheck::INVALID;
            }
        });

        $this->enableApplication(['types' => ['totp', 'own']]);
        $this->reauthenticatedPerson();

        $start = $this->started(EnrollmentRequest::of('own'));

        self::assertSame('own-secret', $start->secret?->reveal());
        self::assertNull($start->provisioningUri);
        self::assertSame('own-secret', $this->pendingFactorOf($start)->getSecret());
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), 'correct')->isConfirmed());
    }

    /**
     * A row whose pending factor is gone goes quietly, and what follows it is
     * still looked at; one whose generation has moved on goes as expired.
     *
     * @return void
     */
    public function testAStartClearsWhatIsNoLongerLive(): void
    {
        $user  = $this->reauthenticatedPerson();
        $gone  = $this->startedEmail();
        $other = $this->startedTotp();

        Factor::query()->whereKey($gone->factor?->id)->delete();

        $this->forgetReports();

        $next = $this->startedTotp();

        self::assertSame(['EnrollmentAbandoned', 'EnrollmentStarted'], $this->reportedNames());
        self::assertSame(1, Enrollment::query()->count());
        self::assertNotSame($other->factor?->id, $next->factor?->id);

        VerificationGeneration::advance($user);
        $this->recordFirstFactor($user);
        $this->forgetReports();

        config()->set('mfa.codes.resend_cooldown_seconds', 0);

        $this->startedEmail();

        self::assertSame(['EnrollmentExpired', 'EnrollmentStarted', 'CodeSent'], $this->reportedNames());
    }

    /**
     * Replacing a factor is enrolling the new one and then removing the old:
     * the old one keeps verifying while the new one is pending, which is
     * refused until it is confirmed, and after that both verify.
     *
     * @return void
     */
    public function testAFactorBeingReplacedStaysUsableUntilTheNewOneIsConfirmed(): void
    {
        $user = $this->steppedUpPerson();
        $old  = $user->authFactors()->sole();

        self::assertInstanceOf(Factor::class, $old);

        $start = $this->startedTotp();
        $new   = $this->pendingFactorOf($start);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($old->id, AuthenticatorApp::code($old, -1)))->isVerified());
        self::assertSame(FailureReason::NOT_CONFIRMED, $this->mfa()->verify(Callers::current(), Submission::factor($new->id, $this->appCode($start, -1)))->reason);

        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($old->id, AuthenticatorApp::code($old)))->isVerified());
        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($new->id, $this->appCode($start, 1)))->isVerified());
    }
}
