<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Mail\Mailable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
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
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * A delivered factor's destination is normalised and captured, proved by a code
 * of a purpose of its own, which never works as a sign-in code or the reverse;
 * a code that cannot go leaves nothing behind.
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
final class DeliveredEnrollmentStarterTest extends TestCase
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
     * An email address is trimmed and put in lower case, and a code goes to it
     * even when it is already the identity's own.
     *
     * @return void
     */
    public function testAnEmailAddressIsNormalizedAndProved(): void
    {
        $this->reauthenticatedPerson();

        $start  = $this->started(EnrollmentRequest::delivered('email', '  Person@Example.TEST '));
        $factor = $this->pendingFactorOf($start);

        self::assertSame(self::ADDRESS, $factor->getDestination());
        self::assertCount(1, $this->mailbox->sentTo(self::ADDRESS));
        self::assertNotNull($this->rowOf($start)->challenge_id);
        self::assertSame('pe****@example.test', $start->factor?->maskedDestination);
        self::assertNull($start->secret);
        self::assertNull($start->provisioningUri);
    }

    /**
     * A phone number loses its spaces, dashes and parentheses, and goes in
     * E.164.
     *
     * @return void
     */
    public function testAPhoneNumberIsNormalized(): void
    {
        $this->enableApplication(['types' => ['sms']]);
        $this->reauthenticatedPerson();

        FakeSmsSender::fake($this->container());

        $start = $this->started(EnrollmentRequest::delivered('sms', '+44 (0)-7700 900123'));

        self::assertSame('+4407700900123', $this->pendingFactorOf($start)->getDestination());
    }

    /**
     * A later change to the identity's address does not redirect the codes, and
     * the code confirms.
     *
     * @return void
     */
    public function testALaterChangeOnTheIdentityDoesNotRedirect(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedEmail();

        $user->update(['email' => 'changed@example.test']);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        self::assertTrue($this->mfa()->resendEnrollmentCode($this->grantOf($start))->wasSent());
        self::assertCount(2, $this->mailbox->sentTo(self::ADDRESS));
        self::assertSame([], $this->mailbox->sentTo('changed@example.test'));
        self::assertTrue($this->mfa()->confirmEnrollment($this->grantOf($start), (string) $this->mailbox->lastCodeTo(self::ADDRESS))->isConfirmed());
    }

    /**
     * A delivery that throws leaves no factor, no row, no code and no event.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeliveryThatThrowsLeavesNothing(): void
    {
        $this->reauthenticatedPerson();

        $this->container()->instance(EmailSender::class, new class implements EmailSender {
            /**
             * Fail.
             *
             * @param  string  $address
             * @param  \Illuminate\Contracts\Mail\Mailable  $message
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function send(#[\SensitiveParameter] string $address, #[\SensitiveParameter] Mailable $message): void
            {
                throw new \RuntimeException('The mail server is down.');
            }
        });
        $this->mfa()->forgetDrivers();
        $this->forgetReports();

        try {
            $this->mfa()->startEnrollment(EnrollmentRequest::delivered('email', self::ADDRESS));

            self::fail('A delivery that throws was expected to propagate.');
        } catch (CodeDeliveryFailedException) {
            self::assertSame(0, Factor::query()->count());
            self::assertSame(0, Enrollment::query()->count());
            self::assertSame(0, Code::query()->count());
            self::assertSame([], $this->reported);
        }
    }

    /**
     * A sending cap refuses the start with how long to wait, leaving nothing,
     * and restarting does not reset it.
     *
     * @return void
     */
    public function testASendingCapRollsTheStartBackAndARestartDoesNotResetIt(): void
    {
        config()->set('mfa.codes.identity_send_limit', 1);

        $this->reauthenticatedPerson();

        $this->startedEmail();
        $this->forgetReports();

        $second = $this->mfa()->startEnrollment(EnrollmentRequest::delivered('email', self::ADDRESS));

        self::assertSame(FailureReason::SENDING_CAPPED, $second->reason);
        self::assertSame(3600, $second->retryAfter);
        self::assertSame('The enrolment\'s first code was not sent.', (new CodeNotSentException(SendResult::refused(FailureReason::SENDING_CAPPED)))->getMessage());
        self::assertSame([], $this->reported);
        self::assertSame(1, Enrollment::query()->count());
        self::assertSame(1, Code::query()->count());
    }

    /**
     * Restarting leaves the sends to a destination counted, although each
     * restart makes a new factor: the cap on them refuses, keeping the
     * enrolment under way, while another destination may still be sent to.
     *
     * @return void
     */
    public function testARestartDoesNotResetTheCapOnADestination(): void
    {
        config()->set('mfa.codes.factor_send_limit', 2);
        config()->set('mfa.codes.resend_cooldown_seconds', 0);

        $this->reauthenticatedPerson();

        $this->startedEmail();

        $second = $this->startedEmail();
        $third  = $this->mfa()->startEnrollment(EnrollmentRequest::delivered('email', self::ADDRESS));

        self::assertSame(FailureReason::SENDING_CAPPED, $third->reason);
        self::assertSame(3600, $third->retryAfter);
        self::assertTrue($this->rowOf($second)->exists);
        self::assertTrue($this->startedEmail('other@example.test')->hasStarted());
    }

    /**
     * Restarting waits out the cooldown since the last code to the destination,
     * as a resend does, keeping the enrolment under way, and cancelling first
     * makes no difference; another destination need not wait.
     *
     * @return void
     */
    public function testARestartWaitsOutTheCooldownOfADestination(): void
    {
        $this->reauthenticatedPerson();

        $first   = $this->startedEmail();
        $restart = $this->mfa()->startEnrollment(EnrollmentRequest::delivered('email', self::ADDRESS));

        self::assertSame(FailureReason::SENDING_CAPPED, $restart->reason);
        self::assertSame(60, $restart->retryAfter);
        self::assertTrue($this->rowOf($first)->exists);
        self::assertTrue($this->mfa()->cancelEnrollment($this->grantOf($first)));
        self::assertSame(60, $this->mfa()->startEnrollment(EnrollmentRequest::delivered('email', self::ADDRESS))->retryAfter);
        self::assertTrue($this->startedEmail('other@example.test')->hasStarted());

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(60));

        $this->reauthenticatedPerson();

        self::assertTrue($this->startedEmail()->hasStarted());
    }

    /**
     * An enrolment code does not work as a sign-in or a step-up code, and a
     * sign-in code does not work for enrolment.
     *
     * @return void
     */
    public function testCodesOfOnePurposeMatchNothingElse(): void
    {
        $user  = $this->steppedUpPerson();
        $start = $this->startedEmail();
        $code  = (string) $this->mailbox->lastCodeTo(self::ADDRESS);
        $row   = $this->rowOf($start);

        $submission = Submission::challenge((string) $start->factor?->id, (string) $row->challenge_id, $code);

        self::assertSame(FailureReason::NOT_CONFIRMED, $this->mfa()->verify($submission)->reason);
        self::assertSame(FailureReason::NOT_CONFIRMED, $this->mfa()->sendCode($start->factor?->id)->reason);

        $confirmed = $this->emailFactor($user, 'second@example.test');

        [$challenge, $signInCode] = $this->sentCode($confirmed, Purpose::STEP_UP);

        $row->update(['factor_id' => $confirmed->id, 'challenge_id' => $challenge]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment($this->grantOf($start), $signInCode)->reason);
    }

    /**
     * A code answering nothing the enrolment knows counts nothing, and a used
     * one reports as the gateway does.
     *
     * @return void
     */
    public function testAChallengeThatIsGoneCountsNothing(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedEmail();
        $code  = (string) $this->mailbox->lastCodeTo(self::ADDRESS);

        $this->rowOf($start)->update(['challenge_id' => null]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment($this->grantOf($start), $code)->reason);
        self::assertSame(0, $this->rowOf($start)->attempts);

        $this->rowOf($start)->update(['challenge_id' => Code::query()->value('id')]);

        Code::query()->update(['expires_at' => CarbonImmutable::now()->subSecond()]);

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->confirmEnrollment($this->grantOf($start), $code)->reason);
        self::assertSame(0, $this->rowOf($start)->attempts);
        self::assertSame(0, $this->addressHits('127.0.0.1'));
    }

    /**
     * The confirming code passes once, naming its challenge on the events.
     *
     * @return void
     */
    public function testAConfirmationNamesItsChallenge(): void
    {
        $this->reauthenticatedPerson();

        $start     = $this->startedEmail();
        $challenge = $this->rowOf($start)->challenge_id;

        $this->forgetReports();

        self::assertTrue($this->mfa()->confirmEnrollment($this->grantOf($start), (string) $this->mailbox->lastCodeTo(self::ADDRESS))->isConfirmed());

        self::assertInstanceOf(VerificationPassed::class, $this->reported[0]);
        self::assertSame($challenge, $this->reported[0]->challengeId);
        self::assertNotNull(Code::query()->value('consumed_at'));
    }

    /**
     * Under an enrolment binding only a pending factor holding a live enrolment
     * bound to the caller is admitted; a confirmed one, one with none, one that
     * expired and another session's are refused.
     *
     * @return void
     */
    public function testAnEnrollmentChallengeAdmitsOnlyAPendingFactorWithALiveEnrollment(): void
    {
        $user  = $this->steppedUpPerson();
        $start = $this->startedEmail();

        $pending   = $this->pendingFactorOf($start);
        $confirmed = Factor::query()->where('status', 'confirmed')->sole();
        $binding   = $this->enrollmentBinding($user);
        $counters  = $this->container()->make(ChallengeCounters::class);
        $admit     = static fn (Factor $factor, ProofBinding $on): ?FailureReason => DB::transaction(
            static fn (): ?FailureReason => $counters->isUsable($user, $factor, $on)->reason,
        );
        $elsewhere = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, 'another-sign-in', Purpose::ENROLLMENT);
        $stepUp    = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, Purpose::STEP_UP);

        self::assertNull($admit($pending, $binding));
        self::assertSame(FailureReason::NOT_FOUND, $admit($confirmed, $binding));
        self::assertSame(FailureReason::NOT_FOUND, $admit($pending, $elsewhere));
        self::assertSame(FailureReason::NOT_CONFIRMED, $admit($pending, $stepUp));

        $this->rowOf($start)->update(['expires_at' => CarbonImmutable::now()]);

        self::assertSame(FailureReason::EXPIRED, $admit($pending, $binding));

        $this->rowOf($start)->delete();

        self::assertSame(FailureReason::NOT_FOUND, $admit($pending, $binding));

        config()->set('mfa.applications.' . self::APPLICATION . '.types', ['totp']);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $admit($pending, $binding));
    }

    /**
     * A report under an enrolment binding changes no count either way, and
     * still refuses a binding naming another identity.
     *
     * @return void
     */
    public function testAReportUnderAnEnrollmentBindingChangesNoCount(): void
    {
        $user     = $this->steppedUpPerson();
        $factor   = Factor::query()->where('status', 'confirmed')->sole();
        $binding  = $this->enrollmentBinding($user);
        $counters = $this->container()->make(ChallengeCounters::class);

        $factor->update(['consecutive_failures' => 2]);

        $failed = DB::transaction(static fn () => $counters->report($user, $factor, $binding, false));
        $passed = DB::transaction(static fn () => $counters->report($user, $factor, $binding, true));

        self::assertFalse($failed->passed);
        self::assertTrue($failed->isFailed());
        self::assertTrue($passed->passed);
        self::assertSame(2, $this->factorRun($factor));
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * A credential that allows sending a code does not reach a pending factor's
     * challenge, and one lacking the bootstrap actions is refused.
     *
     * @return void
     */
    public function testACredentialNeedsTheEnrollmentActions(): void
    {
        $user    = $this->bootstrapPerson();
        $start   = $this->startedEmail();
        $factor  = $this->pendingFactorOf($start);
        $binding = new ProofBinding($user->getMorphClass(), (string) $user->id, self::APPLICATION, self::PENDING, Purpose::ENROLLMENT);
        $gateway = $this->container()->make(ChallengeGateway::class);
        $code    = (string) $this->mailbox->lastCodeTo(self::ADDRESS);
        $row     = $this->rowOf($start);

        $this->pendingSession($user, null, [PendingAction::SEND_CODE, PendingAction::VERIFY]);

        self::assertSame(FailureReason::NOT_FOUND, $gateway->send($factor, $binding)->reason);
        self::assertSame(FailureReason::NOT_FOUND, $gateway->verify($factor, $binding, (string) $row->challenge_id, $code)->reason);

        $this->pendingSession($user, null, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]);

        self::assertSame(FailureReason::NOT_FOUND, $gateway->send($factor, $binding)->reason);
        self::assertNull($gateway->verify($factor, $binding, (string) $row->challenge_id, $code)->reason);
    }

    /**
     * What an active person's enrolment is bound to.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function enrollmentBinding(TestUser $user): ProofBinding
    {
        return new ProofBinding($user->getMorphClass(), (string) $user->id, self::APPLICATION, self::SESSION, Purpose::ENROLLMENT);
    }
}
