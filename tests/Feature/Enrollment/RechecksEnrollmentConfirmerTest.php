<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
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
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * What confirming checks again inside its transaction; freshness is not one of
 * them, and no refusal spends the code.
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
final class RechecksEnrollmentConfirmerTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * Reported against the factor.
     *
     * @return void
     */
    public function testAnIdentityGoneInactiveIsRefused(): void
    {
        $identity = new NonEloquentIdentity('person-1', active: true);

        $this->actingAs($identity);

        $store = $this->container()->make(ProofStore::class);

        $store->begin($identity, self::APPLICATION, self::SESSION);
        $store->record($identity, SignInProofs::of($identity)->inSession(self::SESSION)->password(60));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $inactive = new NonEloquentIdentity('person-1', active: false);

        $this->actingAs($inactive);

        $this->forgetReports();

        // Not its first factor, so nothing later would refuse it instead.
        $this->rowOf($start)->update(['authority' => 'step_up']);

        Factor::query()->create([
            'authenticatable_type' => $this->pendingFactorOf($start)->authenticatable_type,
            'authenticatable_id'   => $this->pendingFactorOf($start)->authenticatable_id,
            'type'                 => 'email',
            'destination'          => 'other@example.test',
            'status'               => 'confirmed',
        ]);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertSame($start->factor?->id, $this->failureReported()->factor?->id);
        self::assertSame('totp', $this->failureReported()->type);
        self::assertSame(Purpose::ENROLLMENT, $this->failureReported()->purpose);
        self::assertSame(0, $this->rowOf($start)->attempts);
        self::assertNull($this->pendingFactorOf($start)->getLastAcceptedStep());
    }

    /**
     * With when it lifts, spending nothing.
     *
     * @return void
     */
    public function testAnIdentityLockedMeanwhileIsRefused(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();
        $code  = $this->appCode($start);
        $owner = ProofOwner::of($user);
        $until = CarbonImmutable::now()->addMinutes(5);

        IdentityState::query()->updateOrCreate(['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key], ['locked_until' => $until]);

        $this->forgetReports();

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code);

        self::assertSame(FailureReason::LOCKED, $confirmation->reason);
        self::assertSame($until->getTimestamp(), $confirmation->lockedUntil?->getTimestamp());
        self::assertSame(FailureReason::LOCKED, $this->failureReported()->reason);
        self::assertSame(0, $this->rowOf($start)->attempts);
        self::assertNull($this->pendingFactorOf($start)->getLastAcceptedStep());
    }

    /**
     * @return void
     */
    public function testATypeNoLongerEnabledIsRefused(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->enableApplication(['types' => ['email']]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
    }

    /**
     * Those through another application do not count.
     *
     * @return void
     */
    public function testALimitReachedMeanwhileIsRefused(): void
    {
        $this->enableApplication(['limits' => ['confirmed' => 2]]);

        $user  = $this->steppedUpPerson();
        $start = $this->startedEmail();
        $code  = $this->mailbox->lastCodeTo(self::ADDRESS);
        $other = $this->emailFactor($user, 'second@example.test', ['application' => self::APPLICATION]);

        self::assertNotNull($code);
        self::assertSame(FailureReason::LIMIT_REACHED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);

        $other->update(['application' => 'admin']);

        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->isConfirmed());
    }

    /**
     * Switched off, or no longer allowing the type.
     *
     * @return void
     */
    public function testBootstrapChangedMeanwhileIsRefused(): void
    {
        $this->bootstrapPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->enableApplication(['bootstrap' => ['enabled' => false]]);

        self::assertSame(FailureReason::MFA_ENROLLMENT_REQUIRED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);

        $this->enableApplication(['bootstrap' => ['enabled' => true, 'types' => ['email']]]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
    }

    /**
     * Bootstrap and reauthentication grants rested on having none; a step-up
     * grant is left alone.
     *
     * @return void
     */
    public function testAConfirmedFactorAppearingRefusesWhatHavingNoneAuthorized(): void
    {
        $user  = $this->bootstrapPerson();
        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->totpFactor($user, ['application' => 'admin']);

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);

        Factor::query()->where('status', 'confirmed')->delete();

        $this->noPendingSession();

        $other = $this->reauthenticatedPerson();
        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->totpFactor($other, ['application' => 'admin']);

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);

        $this->rowOf($start)->update(['authority' => 'step_up']);

        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->isConfirmed());
    }

    /**
     * The grant already ends with the proof that authorised it.
     *
     * @return void
     */
    public function testFreshnessIsNotJudgedAgain(): void
    {
        $user = $this->steppedUpPerson();

        $start = $this->startedTotp();

        $this->container()->make(ProofStore::class)->forgetFactor($user, Factor::query()->where('status', 'confirmed')->sole()->id);

        self::assertFalse($this->mfa()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());
    }

    /**
     * The code's step rolls back with everything else.
     *
     * @return void
     */
    public function testAnActiveFirstFactorThePolicyRejectsRollsBack(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedEmail();
        $code  = $this->mailbox->lastCodeTo(self::ADDRESS);

        self::assertNotNull($code);

        $store = $this->container()->make(ProofStore::class);

        $store->forget($user, self::APPLICATION);
        $store->begin($user, self::APPLICATION, self::SESSION);
        $store->record($user, $this->emailFirstFactor($user, self::SESSION));

        $this->forgetReports();

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code);

        self::assertSame(FailureReason::NOT_ACCEPTED, $confirmation->reason);
        self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
        self::assertTrue($this->rowOf($start)->exists);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->failureReported()->reason);
        self::assertSame(FactorStatus::PENDING, $this->failureReported()->factor?->status);
        self::assertSame('email', $this->failureReported()->type);
        self::assertSame($this->rowOf($start)->challenge_id, $this->failureReported()->challengeId);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
    }

    /**
     * It may serve another sign-in.
     *
     * @return void
     */
    public function testALaterFactorIsNotJudgedAgainstTheFirstFactor(): void
    {
        $user  = $this->steppedUpPerson();
        $start = $this->startedEmail();
        $code  = (string) $this->mailbox->lastCodeTo(self::ADDRESS);
        $store = $this->container()->make(ProofStore::class);

        $store->forget($user, self::APPLICATION);
        $store->begin($user, self::APPLICATION, self::SESSION);
        $store->record($user, $this->emailFirstFactor($user, self::SESSION));

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code);

        self::assertTrue($confirmation->isConfirmed());
        self::assertFalse($confirmation->abandoned);
    }
}
