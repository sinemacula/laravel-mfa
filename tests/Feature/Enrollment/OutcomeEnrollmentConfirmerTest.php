<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
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
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\Fixtures\Verification\Dumps;
use Tests\TestCase;

/**
 * What a confirmation does for the session: on a pending one its proof goes to
 * `PendingCompletion` with the whole requirement evaluated again; on an active
 * one no proof is recorded and a shortfall goes to `SessionTransition`; recovery
 * codes come with the first factor; and a refusal rolls all of it back.
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
final class OutcomeEnrollmentConfirmerTest extends TestCase
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
     * On a pending session the proof reaches the completion with the
     * enrolment's purpose, and the whole requirement is evaluated with it.
     *
     * @return void
     */
    public function testAPendingSessionsProofReachesTheCompletion(): void
    {
        $user       = $this->bootstrapPerson(Requirement::none()->withAdditionalVerification());
        $completion = new \stdClass;
        $seam       = new CheckingCompletion(self::PENDING, completion: $completion);
        $transition = new RecordingSessionTransition(new \stdClass);

        $this->container()->instance(PendingCompletion::class, $seam);
        $this->container()->instance(SessionTransition::class, $transition);

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertTrue($confirmation->isConfirmed());
        self::assertCount(1, $seam->accepted);
        self::assertSame([], $transition->changes);
        self::assertNull($confirmation->completion());

        $result = $confirmation->verification;

        self::assertNotNull($result);
        self::assertNotNull($result->proof);
        self::assertSame($completion, $result->completion());
        self::assertSame(Purpose::ENROLLMENT, $result->proof->binding->purpose);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $result->proof->kind);
        self::assertSame('totp', $result->type);
        self::assertSame(['otp'], $result->amr);
        self::assertSame($start->factor?->id, $result->proof->reference);
        self::assertTrue($result->evaluation?->meetsRequirement());
        self::assertSame((string) $user->id, $result->proof->binding->identityKey);
    }

    /**
     * A new factor that cannot meet the requirement leaves the session pending,
     * which is not a failure: the proof was accepted.
     *
     * @return void
     */
    public function testARequirementTheNewFactorCannotMeetLeavesItPending(): void
    {
        $this->bootstrapPerson(Requirement::none()->withPhishingResistance());

        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame([RequirementPart::PHISHING_RESISTANCE], $confirmation->verification?->evaluation?->unmet);
    }

    /**
     * The default completion records the proof, once it commits, on the pending
     * session the store holds.
     *
     * @return void
     */
    public function testTheDefaultCompletionRecordsTheProof(): void
    {
        $user  = $this->bootstrapPerson();
        $start = $this->startedTotp();

        $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        $proofs = $this->furtherProofs($user);

        self::assertCount(1, $proofs);
        self::assertSame(Purpose::ENROLLMENT, $proofs[0]->binding->purpose);
    }

    /**
     * A completion's refusal rolls back the code's use, the step, the
     * confirmation, the end of the obligation and the recovery codes.
     *
     * @return void
     */
    public function testACompletionsRefusalRollsEverythingBack(): void
    {
        $user = $this->bootstrapPerson();

        $this->obligeToEnroll($user);

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->container()->instance(PendingCompletion::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The session refused it.')));
        $this->forgetReports();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertSame(FailureReason::NOT_ACCEPTED, $confirmation->reason);
        self::assertSame([], $confirmation->recoveryCodes);
        self::assertNull($confirmation->verification);
        self::assertSame(['VerificationFailed'], $this->reportedNames());
        self::assertSame(FactorStatus::PENDING, $this->failureReported()->factor?->status);

        $factor = $this->pendingFactorOf($start);

        self::assertFalse($factor->isConfirmed());
        self::assertNull($factor->getLastAcceptedStep());
        self::assertTrue($this->rowOf($start)->exists);
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertTrue(ReenrollmentObligation::isRequired($user));
        self::assertSame(0, $this->addressHits('127.0.0.1'));
    }

    /**
     * Any other failure of the completion propagates, and rolls back as well.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnyOtherFailureOfTheCompletionPropagates(): void
    {
        $this->bootstrapPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->container()->instance(PendingCompletion::class, new RefusingCompletion(new ProofRefusedException('The store is gone.')));

        try {
            $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

            self::fail('The failure was expected to propagate.');
        } catch (ProofRefusedException) {
            self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
        }
    }

    /**
     * On a pending session a factor the policy will not accept after the first
     * factor is refused at confirmation too.
     *
     * @return void
     */
    public function testABootstrapProofNotAcceptedIsRefused(): void
    {
        $user  = $this->bootstrapPerson();
        $start = $this->startedEmail();
        $code  = (string) $this->mailbox->lastCodeTo(self::ADDRESS);

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS, firstFactor: $this->emailFirstFactor($user, self::PENDING));

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->confirmEnrollment($this->grantOf($start), $code)->reason);
        self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
    }

    /**
     * On an active session no proof is recorded and `StepUp` is not called;
     * the bound transition judges the session again all the same, told the
     * sign-in, the factor and that the requirement is still met, and what it
     * returns is the confirmation's completion.
     *
     * @return void
     */
    public function testAnActiveSessionRecordsNoProof(): void
    {
        $user       = $this->reauthenticatedPerson();
        $stepUp     = new CheckingCompletion(self::SESSION);
        $completion = new \stdClass;
        $transition = new RecordingSessionTransition($completion);

        $this->container()->instance(StepUp::class, $stepUp);
        $this->container()->instance(SessionTransition::class, $transition);

        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertNull($confirmation->verification);
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $stepUp->accepted);
        self::assertCount(1, $transition->changes);
        self::assertSame($completion, $confirmation->completion());

        $change = $transition->changes[0];

        self::assertSame(FactorChangeMade::CONFIRMED, $change->change);
        self::assertSame(self::SESSION, $change->session);
        self::assertSame(self::APPLICATION, $change->application);
        self::assertSame($start->factor?->id, $change->factor->id);
        self::assertSame(FactorStatus::CONFIRMED, $change->factor->status);
        self::assertEquals($user->getAuthIdentifier(), $change->identity->getAuthIdentifier());
        self::assertNull($change->outstanding);
    }

    /**
     * A transition's refusal on an active session rolls the confirmation back:
     * the factor stays pending and no recovery codes are kept.
     *
     * @return void
     */
    public function testATransitionsRefusalRollsTheConfirmationBack(): void
    {
        $this->reauthenticatedPerson();

        $transition = self::createStub(SessionTransition::class);
        $transition->method('factorChanged')->willThrowException(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Cannot judge the session.'));

        $this->container()->instance(SessionTransition::class, $transition);

        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertSame(FailureReason::NOT_ACCEPTED, $confirmation->reason);
        self::assertNull($confirmation->completion());
        self::assertFalse($this->pendingFactorOf($start)->isConfirmed());
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * On an application that requires a verification of an identity with a
     * factor, the first factor leaves an active session short, which goes to
     * the bound transition.
     *
     * @return void
     */
    public function testAShortfallGoesToTheTransition(): void
    {
        $this->enableApplication(['requirement' => 'enrolled']);

        $this->reauthenticatedPerson();

        $transition = new RecordingSessionTransition;

        $this->container()->instance(SessionTransition::class, $transition);

        $start = $this->startedTotp();

        self::assertTrue($this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start))->isConfirmed());
        self::assertCount(1, $transition->shortfalls());
        self::assertSame(self::APPLICATION, $transition->changes[0]->application);
        self::assertTrue($transition->changes[0]->outstanding?->asks(RequirementPart::ADDITIONAL_VERIFICATION));
    }

    /**
     * Recovery codes come with the first factor, returned once, and are hidden
     * from every dump; a later factor brings none.
     *
     * @return void
     */
    public function testRecoveryCodesComeWithTheFirstFactorOnly(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertCount(10, $confirmation->recoveryCodes);
        self::assertInstanceOf(RevealedSecret::class, $confirmation->recoveryCodes[0]);
        self::assertSame(10, RecoveryCode::query()->count());

        $plain = $confirmation->recoveryCodes[0]->reveal();

        foreach (Dumps::of($confirmation) as $way => $dump) {
            self::assertStringNotContainsString($plain, $dump, $way);
        }

        $this->recordStepUp($user, Factor::query()->sole());

        $second = $this->startedEmail();
        $later  = $this->mfa()->confirmEnrollment($this->grantOf($second), (string) $this->mailbox->lastCodeTo(self::ADDRESS));

        self::assertTrue($later->isConfirmed());
        self::assertSame([], $later->recoveryCodes);
        self::assertSame(10, RecoveryCode::query()->count());
    }

    /**
     * Recovery codes do not come where they are disabled, nor below the level
     * the application issues them at.
     *
     * @return void
     */
    public function testRecoveryCodesRespectTheApplication(): void
    {
        $this->enableApplication(['recovery_codes' => ['enabled' => false]]);
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        self::assertSame([], $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start))->recoveryCodes);

        Factor::query()->delete();

        // An email code after a password reaches AAL1 only.
        $this->enableApplication(['recovery_codes' => ['enabled' => true, 'level' => AssuranceLevel::AAL2->value]]);

        $second = $this->startedEmail();

        self::assertSame([], $this->mfa()->confirmEnrollment($this->grantOf($second), (string) $this->mailbox->lastCodeTo(self::ADDRESS))->recoveryCodes);
        self::assertSame(0, RecoveryCode::query()->count());

        Factor::query()->delete();

        $this->enableApplication(['recovery_codes' => ['enabled' => true, 'level' => AssuranceLevel::AAL1->value]]);

        $third = $this->startedEmail('other@example.test');

        self::assertCount(10, $this->mfa()->confirmEnrollment($this->grantOf($third), (string) $this->mailbox->lastCodeTo('other@example.test'))->recoveryCodes);
    }

    /**
     * With the session's first factor not known no codes are issued, though the
     * factor is confirmed.
     *
     * @return void
     */
    public function testNoRecoveryCodesWithoutAKnownFirstFactor(): void
    {
        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(null));
        $this->enableApplication(['first_factor' => null]);

        $user  = $this->signedInPerson();
        $store = $this->container()->make(ProofStore::class);

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame([], $confirmation->recoveryCodes);
        self::assertSame((string) $user->id, Factor::query()->sole()->authenticatable_id);
    }

    /**
     * Confirming ends the obligation to enrol again, on both kinds of session.
     *
     * @return void
     */
    public function testConfirmingEndsTheObligation(): void
    {
        $user = $this->reauthenticatedPerson();

        $this->obligeToEnroll($user);

        self::assertTrue(ReenrollmentObligation::isRequired($user));

        $start = $this->startedTotp();

        $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertFalse(ReenrollmentObligation::isRequired($user));

        $pending = $this->bootstrapPerson();

        $this->obligeToEnroll($pending);

        $second = $this->startedTotp();

        $this->mfa()->confirmEnrollment($this->grantOf($second), $this->appCode($second));

        self::assertFalse(ReenrollmentObligation::isRequired($pending));
    }

    /**
     * The default completion takes an enrolment's additional factor on a
     * pending session, and no other kind of proof made for enrolling.
     *
     * @return void
     */
    public function testTheDefaultCompletionRefusesAnyOtherProofOfAnEnrollment(): void
    {
        $user    = $this->bootstrapPerson();
        $pending = $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);
        $proofs  = SignInProofs::of($user)->inSession(self::PENDING);
        $binding = new ProofBinding($proofs->identityType, $proofs->identityKey, self::APPLICATION, self::PENDING, Purpose::STEP_UP);

        $this->expectException(OperationRefusedException::class);

        $this->container()->make(ProofStoreCompletion::class)->complete($pending, VerificationResult::verified(
            new Proof(
                ProofKind::ADDITIONAL_FACTOR,
                'totp',
                new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-1'),
                'factor-1',
                ObservedProperties::none(),
                CarbonImmutable::now(),
                $binding,
                0,
            ),
            new Evaluation(false, false, AssuranceLevel::UNCLASSIFIED, false, false, [], [], []),
            [],
            'totp',
        ));
    }
}
