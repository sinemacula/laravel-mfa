<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\SubmissionRoutes;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\RecordingFactorDriver;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Requirements\RecordingCombinationPolicy;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Requirements\UnacceptingCombinationPolicy;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * A success goes to the pending completion or the step-up as the last write of
 * the transaction, so their refusal undoes the code's use and the count on
 * every route, and the whole requirement is evaluated again after each proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(VerificationResult::class)]
#[CoversClass(SubmissionRoutes::class)]
#[CoversClass(CheckOutcome::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(ChallengeOutcome::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(SendResult::class)]
#[CoversClass(RefusedUnderLockException::class)]
#[CoversClass(SessionFirstFactor::class)]
final class CompletionVerificationServiceTest extends TestCase
{
    use ArrangesVerification;

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
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The default seams record the proof in the store, so the middleware's read
     * of the proofs passes with no write by the verification itself.
     *
     * @return void
     */
    public function testTheDefaultSeamsRecordTheProof(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $before = Mfa::proofs(Callers::current());
        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));
        $after  = Mfa::proofs(Callers::current());

        self::assertSame([], $before);
        self::assertTrue($result->isVerified());
        self::assertCount(1, $after);
        self::assertSame($result->proof?->toArray(), $after[0]->toArray());
        self::assertNull($result->completion());
    }

    /**
     * The routes a submission can take.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function routes(): iterable
    {
        yield from [
            'a code for a factor' => ['totp'],
            'a challenge'         => ['email'],
            'a recovery code'     => ['recovery_code'],
            'an assertion'        => ['passkey'],
        ];
    }

    /**
     * A seam's refusal rolls back the check on every route, and answers with
     * the seam's reason.
     *
     * @param  string  $route
     * @return void
     */
    #[DataProvider('routes')]
    public function testASeamsRefusalRollsEverythingBack(string $route): void
    {
        $this->enablePasskeys();

        $user       = $this->signedInPerson();
        $submission = $this->passingSubmission($user, $route);

        $this->forgetReports();

        Factor::query()->update(['consecutive_failures' => 2]);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_FRESH, 'The adapter refused.')));

        $result = $this->mfa()->verify(Callers::current(), $submission);

        self::assertSame(FailureReason::NOT_FRESH, $result->reason);
        self::assertSame('The adapter refused.', $result->detail);
        self::assertSame(FailureReason::NOT_FRESH, $this->failureReported()->reason);

        $stored = Factor::query()->firstOrFail();

        self::assertSame(2, $stored->getConsecutiveFailures());
        self::assertNull($stored->getLastUsedAt());
        self::assertNull($stored->getLastAcceptedStep());
        self::assertSame(0, Code::query()->whereNotNull('consumed_at')->count());
        self::assertSame(0, RecoveryCode::query()->whereNotNull('used_at')->count());
        self::assertSame([], $this->furtherProofs($user));
    }

    /**
     * A seam's refusal of a code leaves the code usable afterwards.
     *
     * @return void
     */
    public function testACodeARefusalRolledBackStillAnswers(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Refused.')));

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->reason);

        $this->container()->forgetInstance(StepUp::class);
        $this->container()->singleton(StepUp::class, ProofStoreCompletion::class);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());
    }

    /**
     * Any exception from a seam but a refusal propagates, and rolls back too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASeamsOtherExceptionPropagates(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new \LogicException('The adapter is broken.')));

        try {
            $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

            self::fail('The exception must propagate.');
        } catch (\LogicException $exception) {
            self::assertSame('The adapter is broken.', $exception->getMessage());
        }

        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
        self::assertSame([], $this->reported);
    }

    /**
     * A store that refuses the proof at commit is never turned into an ordinary
     * refusal: it propagates, with the code spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStoreRefusalAtCommitPropagatesWithTheCodeSpent(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class), 100, null, true));

        try {
            $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

            self::fail('The store\'s refusal must propagate.');
        } catch (ProofRefusedException) {
            self::assertNotNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
        }
    }

    /**
     * What the seam returns reaches the caller, and a still-pending completion
     * is a success.
     *
     * @return void
     */
    public function testACompletionReachesTheCaller(): void
    {
        $user       = $this->person();
        $factor     = $this->totpFactor($user);
        $completion = new \stdClass;

        $this->pendingSession($user, Requirement::none()->withPhishingResistance(600));

        $seam = new CheckingCompletion('unused', true, $completion);

        $this->container()->instance(PendingCompletion::class, $seam);

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertTrue($result->isVerified());
        self::assertSame($completion, $result->completion());
        self::assertSame([RequirementPart::PHISHING_RESISTANCE], $result->evaluation?->unmet);
        self::assertCount(1, $seam->accepted);
    }

    /**
     * The pending session's completion is handed the caller: its pending
     * session, and the client the verification was served to, with the facts a
     * same-site check reads.
     *
     * @return void
     */
    public function testACompletionIsHandedTheCallerAndItsClient(): void
    {
        $user   = $this->person();
        $factor = $this->totpFactor($user);

        $this->pendingSession($user, Requirement::none());

        $request = $this->container()->make('request');

        $request->headers->set('Origin', 'https://app.example.test');
        $request->headers->set('X-CSRF-Token', 'present');

        $seam = new CheckingCompletion('unused', false);

        $this->container()->instance(PendingCompletion::class, $seam);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertCount(1, $seam->callers);

        $caller = $seam->callers[0];

        self::assertSame($user, $caller->pending?->identity);
        self::assertSame('https://app.example.test', $caller->client->origin);
        self::assertSame($request->getSchemeAndHttpHost(), $caller->client->schemeAndHost);
        self::assertTrue($caller->client->carriesHeader('X_CSRF_TOKEN'));
    }

    /**
     * Requirement parts add up across two verifications of one session.
     *
     * @return void
     */
    public function testARequirementIsEvaluatedAgainAfterEachProof(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withAdditionalVerification()->withPhishingResistance(600)));

        $totp = $this->totpFactor($user);
        $key  = $this->passkeyFactor($user);

        $first = $this->mfa()->verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)));

        self::assertSame([RequirementPart::PHISHING_RESISTANCE], $first->evaluation?->unmet);

        $second = $this->mfa()->verify(Callers::current(), Submission::assertion($key->id, ['id' => self::CREDENTIAL]));

        self::assertTrue($second->evaluation?->meetsRequirement());
        self::assertCount(2, $this->furtherProofs($user));
    }

    /**
     * A pending session's earlier proofs count towards its requirement, and the
     * new proof is handed over even when it still falls short.
     *
     * @return void
     */
    public function testAPendingSessionsEarlierProofsCount(): void
    {
        $this->enablePasskeys();

        $user    = $this->person();
        $key     = $this->passkeyFactor($user);
        $earlier = SignInProofs::of($user)->inSession(self::PENDING)->totp(30);

        $this->pendingSession($user, Requirement::none()->withAdditionalVerification()->withPhishingResistance(600), proofs: [$earlier]);
        $this->beginSignIn($user, self::PENDING);

        $result = $this->mfa()->verify(Callers::current(), Submission::assertion($key->id, ['id' => self::CREDENTIAL]));

        self::assertTrue($result->evaluation?->meetsRequirement());
    }

    /**
     * A pending session's further proofs of another generation or dated in the
     * future do not count.
     *
     * @return void
     */
    public function testAPendingSessionsStaleProofsAreDropped(): void
    {
        $user = $this->person();

        VerificationGeneration::advance($user);

        $totp   = $this->totpFactor($user);
        $policy = new RecordingCombinationPolicy;
        $proofs = SignInProofs::of($user)->inSession(self::PENDING)->underGeneration(1);
        $kept   = $proofs->reauthentication(30);
        $old    = SignInProofs::of($user)->inSession(self::PENDING)->reauthentication(30);
        $future = $proofs->reauthentication(-300);

        $this->container()->instance(CombinationPolicy::class, $policy);

        $this->pendingSession($user, Requirement::none(), proofs: [$old, $kept, $future], firstFactor: $proofs->password(60));
        $this->beginSignIn($user, self::PENDING);

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)));

        self::assertTrue($result->isVerified());
        self::assertSame([$kept, $result->proof], array_slice($policy->handed[1], 1));
    }

    /**
     * A pending session's first factor made before the verification generation
     * advanced proves nothing: every route refuses it before spending anything,
     * whatever a resolver of the application's own still reports.
     *
     * @param  string  $route
     * @return void
     */
    #[DataProvider('routes')]
    public function testAPendingFirstFactorOfAnotherGenerationIsRefused(string $route): void
    {
        $this->enablePasskeys();

        $user = $this->person();

        $this->pendingSession($user);
        $this->beginSignIn($user, self::PENDING);

        $submission = $this->passingSubmission($user, $route);

        $this->forgetReports();

        Factor::query()->update(['consecutive_failures' => 2]);

        VerificationGeneration::advance($user);

        $result = $this->mfa()->verify(Callers::current(), $submission);

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->failureReported()->reason);
        self::assertSame(2, Factor::query()->firstOrFail()->getConsecutiveFailures());
        self::assertSame(0, Code::query()->whereNotNull('consumed_at')->count());
        self::assertSame(0, RecoveryCode::query()->whereNotNull('used_at')->count());
        self::assertSame([], $this->furtherProofs($user));
    }

    /**
     * A pending session's first factor dated in the future proves nothing.
     *
     * @return void
     */
    public function testAPendingFirstFactorDatedInTheFutureIsRefused(): void
    {
        $user   = $this->person();
        $factor = $this->totpFactor($user);
        $proofs = SignInProofs::of($user)->inSession(self::PENDING);

        $this->pendingSession($user, firstFactor: $proofs->password(-300));
        $this->beginSignIn($user, self::PENDING);

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
    }

    /**
     * A listener's refusal after the commit is not the verification's: it
     * propagates, what committed stays, and no failure is reported for an
     * attempt that succeeded.
     *
     * @param  string  $route
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('routes')]
    public function testAListenersRefusalAfterTheCommitPropagates(string $route): void
    {
        $this->enablePasskeys();

        $user       = $this->signedInPerson();
        $submission = $this->passingSubmission($user, $route);

        $this->forgetReports();

        Event::listen(VerificationPassed::class, static function (): void {
            throw new OperationRefusedException(FailureReason::NOT_FRESH, 'A listener refused.');
        });

        try {
            $this->mfa()->verify(Callers::current(), $submission);

            self::fail('The listener\'s refusal must propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame('A listener refused.', $exception->getMessage());
        }

        self::assertCount(1, $this->furtherProofs($user));
        self::assertSame([], array_filter($this->reported, static fn (object $event): bool => $event instanceof VerificationFailed));
        self::assertSame($route === 'email' ? 1 : 0, Code::query()->whereNotNull('consumed_at')->count());
        self::assertSame($route === 'recovery_code' ? 1 : 0, RecoveryCode::query()->whereNotNull('used_at')->count());
    }

    /**
     * A refusal after a passkey verified keeps the challenge the gateway
     * reported, for the failure's event, and still rolls back.
     *
     * @return void
     */
    public function testAPasskeysChallengeSurvivesASeamsRefusal(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $key  = $this->passkeyFactor($user);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Refused.')));

        $result = $this->mfa()->verify(Callers::current(), Submission::assertion($key->id, ['id' => self::CREDENTIAL]));

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertSame('passkey-challenge', $this->failureReported()->challengeId);
        self::assertNull(Factor::query()->whereKey($key->id)->sole()->getLastUsedAt());
        self::assertSame([], $this->furtherProofs($user));
    }

    /**
     * A failed assertion reports no challenge, as the gateway names none.
     *
     * @return void
     */
    public function testAFailedAssertionReportsNoChallenge(): void
    {
        $this->enablePasskeys(FailureReason::EXPIRED);

        $user = $this->signedInPerson();
        $key  = $this->passkeyFactor($user);

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->verify(Callers::current(), Submission::assertion($key->id, ['id' => self::CREDENTIAL]))->reason);
        self::assertNull($this->failureReported()->challengeId);
    }

    /**
     * A proof not itself accepted after the first factor is refused and rolled
     * back, even when an older proof makes the session's answer accepted.
     *
     * @return void
     */
    public function testAnOlderAcceptedProofDoesNotExcuseANewOne(): void
    {
        $user   = $this->signedInPerson();
        $older  = $this->totpFactor($user);
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($older->id, AuthenticatorApp::code($older)))->isVerified());

        $this->container()->instance(CombinationPolicy::class, new UnacceptingCombinationPolicy($factor->id));

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
    }

    /**
     * The result's `amr` is this proof's alone, with no `mfa`, including one a
     * driver supplies, and the evaluation's own values stay separate.
     *
     * @return void
     */
    public function testTheResultsAmrLeavesOutMfa(): void
    {
        $this->enableApplication(['types' => ['custom']]);

        $this->mfa()->extend('custom', fn (): RecordingFactorDriver => new RecordingFactorDriver);

        $user   = $this->signedInPerson();
        $factor = $this->factorOf($user, ['type' => 'custom']);

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, 'correct'));

        self::assertSame(['otp', 'custom'], $result->amr);
        self::assertSame('custom', $result->type);
        self::assertContains('mfa', (array) $result->evaluation?->amr);
    }

    /**
     * A custom driver's replay is reported as one.
     *
     * @return void
     */
    public function testACustomDriversReplayIsReported(): void
    {
        $this->enableApplication(['types' => ['custom']]);

        $this->mfa()->extend('custom', fn (): RecordingFactorDriver => new RecordingFactorDriver);

        $user   = $this->signedInPerson();
        $factor = $this->factorOf($user, ['type' => 'custom']);

        self::assertSame(FailureReason::REPLAYED, $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, 'replayed'))->reason);
        self::assertSame(1, $this->factorRun($factor));
    }

    /**
     * A passkey's proof holds what its assertion observed, and a TOTP code's
     * observes nothing.
     *
     * @return void
     */
    public function testObservedPropertiesAreHonest(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $key  = $this->passkeyFactor($user);
        $totp = $this->totpFactor($user);

        $passkey = $this->mfa()->verify(Callers::current(), Submission::assertion($key->id, ['id' => self::CREDENTIAL]));
        $proof   = $passkey->proof;

        self::assertNotNull($proof);
        self::assertEquals(new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true), $proof->properties);
        self::assertSame(AssuranceLevel::AAL2, $passkey->evaluation?->level);
        self::assertSame('passkey-challenge', $proof->challengeId);
        self::assertSame((new Channel(ChannelKind::PASSKEY, self::CREDENTIAL))->toArray(), $proof->channel?->toArray());
        self::assertContains('pop', $passkey->amr);
        self::assertContains('user', $passkey->amr);

        $code  = $this->mfa()->verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)));
        $proof = $code->proof;

        self::assertNotNull($proof);
        self::assertEquals(ObservedProperties::none(), $proof->properties);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proof->kind);
        self::assertSame($totp->id, $proof->reference);
        self::assertSame('totp', $proof->method);
        self::assertSame(ChannelKind::AUTHENTICATOR_APP, $proof->channel?->kind);
        self::assertSame(VerificationGeneration::current($user), $proof->generation);
        self::assertTrue(CarbonImmutable::now()->equalTo($proof->provedAt));
    }

    /**
     * A recovery code's proof is of its own kind, on no channel and naming no
     * factor, and the factor's last use is stamped only by the factor's route.
     *
     * @return void
     */
    public function testARecoveryCodesProofIsOfItsOwnKind(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = $this->recoveryCode($user);

        $result = $this->mfa()->verify(Callers::current(), Submission::recoveryCode($code), Purpose::SIGN_IN);
        $proof  = $result->proof;

        self::assertNotNull($proof);
        self::assertSame(ProofKind::RECOVERY_CODE, $proof->kind);
        self::assertSame('recovery_code', $proof->method);
        self::assertSame('recovery_code', $result->type);
        self::assertNull($proof->channel);
        self::assertNull($proof->reference);
        self::assertSame(['otp'], $result->amr);
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastUsedAt());

        $factorCode = AuthenticatorApp::code($factor);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $factorCode))->isVerified());
        self::assertNotNull(Factor::query()->whereKey($factor->id)->sole()->getLastUsedAt());
    }

    /**
     * A seam an adapter binds replaces the store: nothing is recorded there,
     * and the proof it is handed is the one the caller gets.
     *
     * @return void
     */
    public function testABoundSeamReplacesTheStore(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $seam   = new CheckingCompletion(self::SESSION);

        $this->container()->instance(StepUp::class, $seam);

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertCount(1, $seam->accepted);
        self::assertSame([], $this->furtherProofs($user));
        self::assertTrue($result->isVerified());
        self::assertSame($seam->accepted[0]->proof, $result->proof);
    }
}
