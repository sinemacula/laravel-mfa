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
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Exceptions\CommitFailedException;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\Fixtures\Verification\IssuedTokens;
use Tests\Fixtures\Verification\TokenIssuingCompletion;
use Tests\TestCase;

/**
 * What a completion returns, its tokens and cookie included, can never reach a
 * response if the storage connection's commit fails: the failure reaches the
 * caller of the verification in its place, and nothing of the sign-in is left.
 *
 * The failure is raised by a listener on `TransactionCommitting`, as Laravel's
 * `transaction()` commits on the PDO directly. It leaves the PDO's transaction
 * open, as a commit the database refused might, so each test rolls that back
 * before it reads durable state, and pending writes are not taken for a
 * rollback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(EnrollmentConfirmer::class)]
final class CommitFailureTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string The route a person verifies on. */
    private const string ROUTE = 'sign-in/verify';

    /** @var bool Whether the next commit on the storage connection fails. */
    private bool $failNextCommit = false;

    /** @var false|string The setting that keeps arguments out of an exception's trace, as it was. */
    private false|string $ignoredArguments = false;

    /**
     * Arrange the application, keep arguments in an exception's trace so they
     * can be searched, bind the completion that issues tokens, and listen for
     * commits on the storage connection.
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
     * Put the setting back.
     *
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
     * A commit failing on a pending session's verification reaches the caller,
     * with no result, and leaves the code unspent, no proof and no event.
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

        $this->assertTheCommitFailureReachesTheCaller(static fn (): VerificationResult => Mfa::verify($submission));

        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->last_used_at);
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->passedReports());

        $retried = Mfa::verify($submission);

        self::assertTrue($retried->isVerified(), 'The code must still be unspent.');
        self::assertInstanceOf(IssuedTokens::class, $retried->completion());
    }

    /**
     * The same for a step-up on an active session.
     *
     * @return void
     */
    public function testAStepUpNeverAnswers(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        $factor     = $this->totpFactor($user);
        $submission = Submission::factor($factor->id, AuthenticatorApp::code($factor));

        $this->assertTheCommitFailureReachesTheCaller(static fn (): VerificationResult => Mfa::verify($submission));

        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->last_used_at);
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->passedReports());

        $retried = Mfa::verify($submission);

        self::assertTrue($retried->isVerified(), 'The code must still be unspent.');
        self::assertCount(1, $this->furtherProofs($user));
    }

    /**
     * The same for confirming an enrolment on a pending session: the factor
     * stays pending, the codes it would have come with are not generated, and
     * the grant and code still work.
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

        $this->assertTheCommitFailureReachesTheCaller(fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment($grant, $code));

        self::assertSame(FactorStatus::PENDING, $this->pendingFactorOf($start)->getStatus());
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertSame([], $this->furtherProofs($user));
        self::assertSame([], $this->passedReports());

        $retried = $this->mfa()->confirmEnrollment($grant, $code);

        self::assertTrue($retried->isConfirmed(), 'The grant and the code must still work.');
        self::assertInstanceOf(IssuedTokens::class, $retried->verification?->completion());
    }

    /**
     * The control: with no failure, the route answers with the token and the
     * cookie, so their absence below means something.
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
     * Through the kernel, a pending verification whose commit fails is a server
     * error with neither the token nor the cookie.
     *
     * @return void
     */
    public function testAFailedCommitOnAPendingVerificationAnswersWithNeither(): void
    {
        $this->assertTheAnswerCarriesNeither($this->arrangedPendingVerification());
    }

    /**
     * The same for a step-up.
     *
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
     * A seam refusing after it began handing over returns a failed result, with
     * nothing a caller could send.
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
        $result = Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertFalse($result->isVerified());
        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertNull($result->completion());
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->last_used_at);
    }

    /**
     * Inside an application's own transaction on the storage connection our
     * commit is a savepoint, so the result reaches its closure first; rolling
     * that transaction back means the cookie is never queued.
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

                $seen = Mfa::verify($submission)->completion();

                throw new MidRotationFailureException('The application changed its mind.');
            });
        } catch (MidRotationFailureException) {
            self::assertInstanceOf(IssuedTokens::class, $seen);
        }

        self::assertFalse($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
    }

    /**
     * An outer commit is what queues the cookie.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOuterCommitQueuesTheCookie(): void
    {
        $submission = $this->arrangedPendingSubmission();

        DB::connection(StorageConnection::name())->transaction(function () use ($submission): void {

            self::assertInstanceOf(IssuedTokens::class, Mfa::verify($submission)->completion());
            self::assertFalse($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
        });

        self::assertTrue($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
    }

    /**
     * Define the route the kernel tests call: it verifies, and answers with the
     * token the completion returned, under the middleware that attaches queued
     * cookies, including to an error response.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->post(self::ROUTE, static function (Request $request): Response {

            $tokens = Mfa::verify(Submission::factor($request->string('factor')->toString(), $request->string('code')->toString()))->completion();

            return new Response($tokens instanceof IssuedTokens ? $tokens->accessToken : 'no token');
        })->middleware(AddQueuedCookiesToResponse::class);
    }

    /**
     * A person on a pending session the store knows of, with a TOTP factor, and
     * what they submit.
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
     * The same, as a submission.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    private function arrangedPendingSubmission(): Submission
    {
        $input = $this->arrangedPendingVerification();

        return Submission::factor($input['factor'], $input['code']);
    }

    /**
     * Fail the next commit, make the call and assert the failure is what the
     * caller receives, with no result anywhere in it, and roll the transaction
     * the failure left open back.
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
            $this->rollBackTheFailedCommit();

            return;
        }

        self::fail('The commit failure must reach the caller.');
    }

    /**
     * Fail the next commit of a request through the kernel, and assert the
     * answer is a server error with neither the token nor the cookie.
     *
     * @param  array{factor: string, code: string}  $input
     * @return void
     */
    private function assertTheAnswerCarriesNeither(array $input): void
    {
        config()->set('app.debug', true);
        config()->set('logging.default', 'null');

        $this->failNextCommit = true;

        $response = $this->postJson(self::ROUTE, $input);

        $this->rollBackTheFailedCommit();

        $response->assertStatus(500);
        $response->assertCookieMissing(TokenIssuingCompletion::COOKIE);

        self::assertStringNotContainsString(TokenIssuingCompletion::ACCESS_TOKEN, (string) $response->baseResponse->getContent());
        self::assertStringNotContainsString(TokenIssuingCompletion::COOKIE_VALUE, (string) $response->baseResponse->getContent());
        self::assertFalse($this->cookies()->hasQueued(TokenIssuingCompletion::COOKIE));
    }

    /**
     * Search the failure, what it wraps and the arguments of every frame of
     * their traces for anything that could carry the completion.
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
     * The failure left the PDO's transaction open: roll it back, so durable
     * state can be read and not what the failed commit had pending.
     *
     * @return void
     */
    private function rollBackTheFailedCommit(): void
    {
        $pdo = DB::connection(StorageConnection::name())->getPdo();

        self::assertTrue($pdo->inTransaction());

        $pdo->rollBack();
    }

    /**
     * What was reported as passed.
     *
     * @return list<\SineMacula\Laravel\Mfa\Events\VerificationPassed>
     */
    private function passedReports(): array
    {
        return array_values(array_filter($this->reported, static fn (object $event): bool => $event instanceof VerificationPassed));
    }

    /**
     * The cookie jar.
     *
     * @return \Illuminate\Cookie\CookieJar
     */
    private function cookies(): CookieJar
    {
        return $this->container()->make(CookieJar::class);
    }
}
