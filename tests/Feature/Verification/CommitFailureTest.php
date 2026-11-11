<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Illuminate\Cookie\CookieJar;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Exceptions\CommitFailedException;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\Fixtures\Verification\IssuedTokens;
use Tests\Fixtures\Verification\TokenIssuingCompletion;
use Tests\TestCase;

/**
 * A failed storage commit reaches the caller in place of the completion. It is
 * raised on `TransactionCommitting`, as `transaction()` commits on the PDO
 * directly, and leaves the PDO's transaction open for the test to roll back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(StorageTransaction::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(PasskeyChangeGate::class)]
final class CommitFailureTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string The route a person verifies on. */
    private const string ROUTE = 'sign-in/verify';

    /** @var string The route a person confirms an enrolment on. */
    private const string CONFIRM_ROUTE = 'sign-in/confirm';

    /** @var string The route a person removes a factor on. */
    private const string REMOVE_ROUTE = 'sign-in/remove';

    /** @var bool Whether the next commit on the storage connection fails. */
    private bool $failNextCommit = false;

    /** @var false|string The setting that keeps arguments out of an exception's trace, as it was. */
    private false|string $ignoredArguments = false;

    /**
     * Keeps arguments in exception traces so they can be searched.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->ignoredArguments = ini_set('zend.exception_ignore_args', '0');

        $completion = $this->container()->make(TokenIssuingCompletion::class);

        $this->container()->instance(PendingCompletion::class, $completion);
        $this->container()->instance(StepUp::class, $completion);

        Event::listen(TransactionCommitting::class, function (TransactionCommitting $event): void {

            if (!$this->failNextCommit || $event->connectionName !== StorageConnection::resolvedName()) {
                return;
            }

            $this->failNextCommit = false;

            throw new CommitFailedException('The database refused the commit.');
        });
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->ignoredArguments !== false) {
            ini_set('zend.exception_ignore_args', $this->ignoredArguments);
        }

        parent::tearDown();
    }

    /**
     * No result reaches it, the code stays unspent, and no proof or event is
     * left.
     *
     * @return void
     */
    public function testAPendingVerificationNeverAnswers(): void
    {
        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $factor     = $this->totpFactor($user);
        $submission = Submission::factor($factor->id, AuthenticatorApp::code($factor));

        $this->assertTheCommitFailureReachesTheCaller(static fn (): VerificationResult => Mfa::verify(Callers::current(), $submission));

        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->last_used_at);
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->passedReports());

        $retried = Mfa::verify(Callers::current(), $submission);

        self::assertTrue($retried->isVerified(), 'The code must still be unspent.');
        self::assertInstanceOf(IssuedTokens::class, $retried->completion());
        self::assertCount(1, $this->furtherProofs($user), 'The failed commit\'s proof must not follow the retry\'s.');
        self::assertCount(1, $this->passedReports(), 'The failed commit\'s report must not follow the retry\'s.');
    }

    /**
     * @return void
     */
    public function testAStepUpNeverAnswers(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        $factor     = $this->totpFactor($user);
        $submission = Submission::factor($factor->id, AuthenticatorApp::code($factor));

        $this->assertTheCommitFailureReachesTheCaller(static fn (): VerificationResult => Mfa::verify(Callers::current(), $submission));

        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->last_used_at);
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->passedReports());

        $retried = Mfa::verify(Callers::current(), $submission);

        self::assertTrue($retried->isVerified(), 'The code must still be unspent.');
        self::assertCount(1, $this->furtherProofs($user), 'The failed commit\'s proof must not follow the retry\'s.');
        self::assertCount(1, $this->passedReports(), 'The failed commit\'s report must not follow the retry\'s.');
    }

    /**
     * The factor stays pending, no recovery codes are generated, and the grant
     * and code still work.
     *
     * @return void
     */
    public function testAPendingEnrollmentConfirmationNeverAnswers(): void
    {
        $user  = $this->bootstrapPerson(Requirement::none()->withAdditionalVerification());
        $start = $this->startedTotp();
        $grant = $this->grantOf($start);
        $code  = $this->appCode($start);

        $this->forgetReports();

        $this->assertTheCommitFailureReachesTheCaller(fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code));

        self::assertSame(FactorStatus::PENDING, $this->pendingFactorOf($start)->getStatus());
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->passedReports());

        $retried = $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code);

        self::assertTrue($retried->isConfirmed(), 'The grant and the code must still work.');
        self::assertInstanceOf(IssuedTokens::class, $retried->verification?->completion());
        self::assertCount(1, $this->furtherProofs($user), 'The failed commit\'s proof must not follow the retry\'s.');
        self::assertCount(1, $this->passedReports(), 'The failed commit\'s report must not follow the retry\'s.');
    }

    /**
     * The control for the tests below.
     *
     * @return void
     */
    public function testWithoutAFailureTheAnswerCarriesTheTokenAndTheCookie(): void
    {
        $response = $this->postJson(self::ROUTE, $this->arrangedPendingVerification());

        $response->assertOk();
        $response->assertSeeText(TokenIssuingCompletion::ACCESS_TOKEN);
        $response->assertCookie(TokenIssuingCompletion::COOKIE, TokenIssuingCompletion::COOKIE_VALUE, false);
    }

    /**
     * A server error, through the kernel.
     *
     * @return void
     */
    public function testAFailedCommitOnAPendingVerificationAnswersWithNeither(): void
    {
        $this->assertTheAnswerCarriesNeither($this->arrangedPendingVerification());
    }

    /**
     * @return void
     */
    public function testAFailedCommitOnAStepUpAnswersWithNeither(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        $factor = $this->totpFactor($user);

        $this->assertTheAnswerCarriesNeither(['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)]);
    }

    /**
     * @return void
     */
    public function testAFailedCommitOnAConfirmationAnswersWithNeither(): void
    {
        $this->bootstrapPerson(Requirement::none()->withAdditionalVerification());

        $start = $this->startedTotp();

        $this->forgetReports();

        $this->assertTheAnswerCarriesNeither(['grant' => $this->grantOf($start), 'code' => $this->appCode($start)], self::CONFIRM_ROUTE);

        $user = TestUser::query()->sole();

        self::assertSame(FactorStatus::PENDING, $this->pendingFactorOf($start)->getStatus());
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->reported);
    }

    /**
     * The factor stays and nothing is reported; the proofs it forgot stay
     * forgotten, so the person verifies again.
     *
     * @return void
     */
    public function testAFailedCommitOnARemovalIsAServerError(): void
    {
        $user  = $this->steppedUpPerson();
        $totp  = Factor::query()->where('type', 'totp')->sole();
        $email = $this->emailFactor($user, attributes: ['application' => self::APPLICATION]);

        $this->forgetReports();

        $this->assertTheAnswerCarriesNeither(['factor' => $email->id], self::REMOVE_ROUTE);

        self::assertTrue(Factor::query()->whereKey($email->id)->exists());
        self::assertSame([], $this->reported);

        $this->recordStepUp($user, $totp);

        self::assertTrue(Mfa::removeFactor(Callers::current(), $email->id)->wasMade());
        self::assertSame(['FactorRemoved'], $this->reportedNames());
    }

    /**
     * The caller's commit is what the association waits for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedOuterCommitOnAPasskeyAssociationLeavesNothing(): void
    {
        $user = $this->reauthenticatedPerson();

        $this->enablePasskeys();
        $this->forgetReports();

        $owner        = ProofOwner::of($user);
        $binding      = new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SESSION, Purpose::ENROLLMENT);
        $registration = new PasskeyRegistration(self::CREDENTIAL, new ObservedProperties(userPresence: true), $binding);
        $gate         = $this->container()->make(PasskeyChangeGate::class);

        $this->failNextCommit = true;

        try {
            DB::connection(StorageConnection::name())->transaction(static function () use ($gate, $user, $registration): void {
                self::assertNotNull($gate->registering(Callers::of($user, self::APPLICATION), $registration));
            });

            self::fail('The commit failure must reach the caller.');
        } catch (CommitFailedException) {
            // The failed transaction is this test's to end, not the package's.
            DB::connection(StorageConnection::name())->getPdo()->rollBack();
        }

        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertSame([], $this->reported);
    }

    /**
     * The seam refuses after it began handing over.
     *
     * @return void
     */
    public function testARefusalAtTheHandOverAnswersWithNoCompletion(): void
    {
        $refusal = new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The session could not complete.');

        $this->container()->instance(PendingCompletion::class, new RefusingCompletion($refusal));

        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $factor = $this->totpFactor($user);
        $result = Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertFalse($result->isVerified());
        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertNull($result->completion());
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->last_used_at);
    }

    /**
     * Inside an application's transaction our commit is a savepoint, so rolling
     * the outer one back means the cookie is never queued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOuterRollbackNeverQueuesTheCookie(): void
    {
        $submission = $this->arrangedPendingSubmission();
        $seen       = null;

        try {
            DB::connection(StorageConnection::name())->transaction(static function () use ($submission, &$seen): void {

                $seen = Mfa::verify(Callers::current(), $submission)->completion();

                throw new MidRotationFailureException('The application changed its mind.');
            });
        } catch (MidRotationFailureException) {
            self::assertInstanceOf(IssuedTokens::class, $seen);
        }

        self::assertFalse($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOuterCommitQueuesTheCookie(): void
    {
        $submission = $this->arrangedPendingSubmission();

        DB::connection(StorageConnection::name())->transaction(function () use ($submission): void {

            self::assertInstanceOf(IssuedTokens::class, Mfa::verify(Callers::current(), $submission)->completion());
            self::assertFalse($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
        });

        self::assertTrue($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
    }

    /**
     * The route verifies and answers with the completion's token, under the
     * middleware that attaches queued cookies, even to errors.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->post(self::ROUTE, static function (Request $request): Response {

            $tokens = Mfa::verify(Callers::current(), Submission::factor($request->string('factor')->toString(), $request->string('code')->toString()))->completion();

            return new Response($tokens instanceof IssuedTokens ? $tokens->accessToken : 'no token');
        })->middleware(AddQueuedCookiesToResponse::class);

        $router->post(self::CONFIRM_ROUTE, static function (Request $request): Response {

            $tokens = Mfa::confirmEnrollment(Callers::current(), $request->string('grant')->toString(), $request->string('code')->toString())->verification?->completion();

            return new Response($tokens instanceof IssuedTokens ? $tokens->accessToken : 'no token');
        })->middleware(AddQueuedCookiesToResponse::class);

        $router->post(self::REMOVE_ROUTE, static function (Request $request): Response {

            $made = Mfa::removeFactor(Callers::current(), $request->string('factor')->toString())->wasMade();

            return new Response($made ? 'removed' : 'refused');
        })->middleware(AddQueuedCookiesToResponse::class);
    }

    /**
     * A person on a pending session with a TOTP factor, and what they submit.
     *
     * @return array{factor: string, code: string}
     */
    private function arrangedPendingVerification(): array
    {
        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $factor = $this->totpFactor($user);

        return ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)];
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    private function arrangedPendingSubmission(): Submission
    {
        $input = $this->arrangedPendingVerification();

        return Submission::factor($input['factor'], $input['code']);
    }

    /**
     * Fails the next commit and rolls back the transaction it leaves open.
     *
     * @param  \Closure(): (\SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation|\SineMacula\Laravel\Mfa\Verification\VerificationResult)  $call
     * @return void
     */
    private function assertTheCommitFailureReachesTheCaller(\Closure $call): void
    {
        $this->failNextCommit = true;

        try {
            $call();
        } catch (CommitFailedException $failure) {
            $this->assertItCarriesNoResult($failure);
            $this->assertTheFailedCommitLeftNoTransaction();

            return;
        }

        self::fail('The commit failure must reach the caller.');
    }

    /**
     * Fails the next commit of a request through the kernel.
     *
     * @param  array<string, string>  $input
     * @param  string  $route
     * @return void
     */
    private function assertTheAnswerCarriesNeither(array $input, string $route = self::ROUTE): void
    {
        config()->set('app.debug', true);
        config()->set('logging.default', 'null');

        $this->failNextCommit = true;

        $response = $this->postJson($route, $input);

        $this->assertTheFailedCommitLeftNoTransaction();

        $response->assertStatus(500);
        $response->assertCookieMissing(TokenIssuingCompletion::COOKIE);

        self::assertStringNotContainsString(TokenIssuingCompletion::ACCESS_TOKEN, (string) $response->baseResponse->getContent());
        self::assertStringNotContainsString(TokenIssuingCompletion::COOKIE_VALUE, (string) $response->baseResponse->getContent());
        self::assertFalse($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
    }

    /**
     * Searches the failure, its previous ones and every frame's arguments for
     * anything that could carry the completion.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function assertItCarriesNoResult(\Throwable $failure): void
    {
        $arguments = [];

        for ($throwable = $failure; $throwable !== null; $throwable = $throwable->getPrevious()) {
            foreach ($throwable->getTrace() as $frame) {
                $arguments = [...$arguments, ...$frame['args'] ?? []];
            }
        }

        self::assertNotSame([], $arguments, 'The trace must keep its arguments for this to mean anything.');

        foreach ($arguments as $argument) {
            self::assertNotInstanceOf(IssuedTokens::class, $argument);
            self::assertNotInstanceOf(VerificationResult::class, $argument);
            self::assertNotInstanceOf(EnrollmentConfirmation::class, $argument);
            self::assertNotSame(TokenIssuingCompletion::ACCESS_TOKEN, $argument);
        }
    }

    /**
     * So what is read next is durable state, not what the failed commit had
     * pending.
     *
     * @return void
     */
    private function assertTheFailedCommitLeftNoTransaction(): void
    {
        self::assertFalse(DB::connection(StorageConnection::name())->getPdo()->inTransaction());
    }

    /**
     * @return list<\SineMacula\Laravel\Mfa\Events\VerificationPassed>
     */
    private function passedReports(): array
    {
        return array_values(array_filter($this->reported, static fn (object $event): bool => $event instanceof VerificationPassed));
    }

    /**
     * @return \Illuminate\Cookie\CookieJar
     */
    private function cookies(): CookieJar
    {
        return $this->container()->make(CookieJar::class);
    }
}
