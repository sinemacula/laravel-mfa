<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\SubmissionRoutes;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * One captured binding (the owner, the application, the sign-in and the
 * purpose) runs through a code's issue, its check and the proof, so a code
 * answers only the sign-in it was sent in, whatever the Laravel session, and a
 * sign-in that changes under a verification spends and reports nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(CallerContextResolver::class)]
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(SubmissionRoutes::class)]
#[CoversClass(CheckOutcome::class)]
#[CoversClass(VerificationResult::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(ChallengeOutcome::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(SendResult::class)]
final class SignInBindingVerificationServiceTest extends TestCase
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
     * A code sent in sign-in A, on one Laravel session, answers nothing once B
     * has begun on that same session, and B's own code works.
     *
     * @return void
     */
    public function testACodeOfAnEndedSignInIsNotFoundUnderTheNext(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->beginSignIn($user, 'sign-in-b');

        $result = $this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame(1, $this->factorRun($factor));

        [$next, $nextCode] = $this->sentCode($factor);

        $passed = $this->mfa()->verify(Submission::challenge($factor->id, $next, $nextCode));

        self::assertTrue($passed->isVerified());
        self::assertSame('sign-in-b', $passed->proof?->binding->sessionId);
    }

    /**
     * A store that switches sign-in between capture and lock refuses the
     * verification as not found, counting, spending and reporting nothing.
     *
     * @return void
     */
    public function testASignInThatChangesUnderAVerificationSpendsNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame([], $this->reported);
        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(0, $this->identityRun($user));
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
        self::assertSame(0, $this->addressHits('127.0.0.1'));
    }

    /**
     * A store that switches sign-in between capture and lock sends nothing.
     *
     * @return void
     */
    public function testASignInThatChangesUnderASendSendsNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        $result = $this->mfa()->sendCode($factor->id);

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame([], $this->mailbox->sent());
        self::assertSame(0, Code::query()->count());
        self::assertSame([], $this->reported);
    }

    /**
     * A guard that fires no event and calls no hook leaves no sign-in, so
     * nothing is sent or verified for it.
     *
     * @return void
     */
    public function testAGuardWithNoSignInIsServedNothing(): void
    {
        $user = $this->person();

        $this->actingAs($user);

        $totp  = $this->totpFactor($user);
        $email = $this->emailFactor($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->sendCode($email->id)->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::factor($totp->id, AuthenticatorApp::code($totp)))->reason);

        self::assertSame([], $this->mailbox->sent());
        self::assertSame([], $this->reported);
        self::assertSame(0, $this->factorRun($totp));
    }

    /**
     * A pending session's code and proof carry its public id, with no sign-in
     * in any other session of the Laravel session.
     *
     * @return void
     */
    public function testAPendingSessionsCodeAndProofCarryItsPublicId(): void
    {
        $user = $this->person();

        $this->pendingSession($user);
        $this->beginSignIn($user, self::PENDING);

        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $result = $this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code));

        self::assertSame($this->bindingOf($user, self::PENDING, Purpose::SIGN_IN), $result->proof?->binding->toArray());
    }

    /**
     * The pending id survives activation, so a code sent while pending answers
     * for the same sign-in and purpose once it is active.
     *
     * @return void
     */
    public function testAPendingCodeAnswersAfterActivationForItsOwnPurpose(): void
    {
        $user = $this->person();

        $this->pendingSession($user);
        $this->beginSignIn($user, self::PENDING);

        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->noPendingSession();
        $this->actingAs($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code))->reason);
        self::assertTrue($this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code), Purpose::SIGN_IN)->isVerified());
    }

    /**
     * A code for a sign-in never answers a step-up, and the reverse.
     *
     * @return void
     */
    public function testACodesPurposeIsBound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$stepUp, $stepUpCode] = $this->sentCode($factor);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::challenge($factor->id, $stepUp, $stepUpCode), Purpose::SIGN_IN)->reason);
        self::assertSame(Purpose::STEP_UP, $this->mfa()->verify(Submission::challenge($factor->id, $stepUp, $stepUpCode))->proof?->binding->purpose);

        [$signIn, $signInCode] = $this->sentCode($factor, Purpose::SIGN_IN);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::challenge($factor->id, $signIn, $signInCode))->reason);
        self::assertSame(Purpose::SIGN_IN, $this->mfa()->verify(Submission::challenge($factor->id, $signIn, $signInCode), Purpose::SIGN_IN)->proof?->binding->purpose);
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
     * A proof names the identity, the application, the session and the purpose,
     * on each route, and the store's own sign-in is the one named.
     *
     * @param  string  $route
     * @return void
     */
    #[DataProvider('routes')]
    public function testAProofsBindingHasAllFourParts(string $route): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        $result = $this->mfa()->verify($this->passingSubmission($user, $route));

        self::assertSame($this->bindingOf($user, self::SESSION, Purpose::STEP_UP), $result->proof?->binding->toArray());
        self::assertCount(1, $this->furtherProofs($user));
    }

    /**
     * The default pending completion refuses a result when the store's current
     * sign-in is not the pending id, and everything rolls back.
     *
     * @return void
     */
    public function testTheDefaultCompletionRefusesAnotherSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->pendingSession($user);

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->failureReported()->reason);
        self::assertSame([], $this->storedProofs($user));
    }

    /**
     * A pending session that does not allow the action serves nothing, and the
     * guard's user is not served in its place.
     *
     * @return void
     */
    public function testAPendingSessionWithoutTheActionIsServedNothing(): void
    {
        $guarded = $this->signedInPerson();
        $factor  = $this->totpFactor($guarded);
        $email   = $this->emailFactor($guarded);
        $user    = $this->person('pending@example.test');

        $this->pendingSession($user, actions: [PendingAction::LIST_FACTORS]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->sendCode($email->id)->reason);
        self::assertSame([], $this->reported);
        self::assertSame([], $this->mfa()->requestAssertion($factor->id));
    }

    /**
     * A pending credential the bound resolver cannot validate is reported by
     * the resolver throwing, which is not caught, and nothing is counted.
     *
     * @return void
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->mfa()->verify(Submission::factor($factor->id, '000000'));
    }
}
