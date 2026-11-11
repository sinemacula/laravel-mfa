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
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\SubmissionRoutes;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * One captured binding of owner, application, sign-in and purpose runs from a
 * code's issue to its proof, so a code answers only the sign-in it was sent in.
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
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * On the same Laravel session, B's own code works.
     *
     * @return void
     */
    public function testACodeOfAnEndedSignInIsNotFoundUnderTheNext(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->beginSignIn($user, 'sign-in-b');

        $result = $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame(1, $this->factorRun($factor));

        [$next, $nextCode] = $this->sentCode($factor);

        $passed = $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $next, $nextCode));

        self::assertTrue($passed->isVerified());
        self::assertSame('sign-in-b', $passed->proof?->binding->sessionId);
    }

    /**
     * The store switches sign-in between capture and lock; nothing is counted,
     * spent or reported.
     *
     * @return void
     */
    public function testASignInThatChangesUnderAVerificationSpendsNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame([], $this->reported);
        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(0, $this->identityRun($user));
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
        self::assertSame(0, $this->addressHits('127.0.0.1'));
    }

    /**
     * The store switches sign-in between capture and lock.
     *
     * @return void
     */
    public function testASignInThatChangesUnderASendSendsNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        $result = $this->mfa()->sendCode(Callers::current(), $factor->id);

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame([], $this->mailbox->sent());
        self::assertSame(0, Code::query()->count());
        self::assertSame([], $this->reported);
    }

    /**
     * A guard that fires no event and calls no hook leaves no sign-in.
     *
     * @return void
     */
    public function testAGuardWithNoSignInIsServedNothing(): void
    {
        $user = $this->person();

        $this->actingAs($user);

        $totp  = $this->totpFactor($user);
        $email = $this->emailFactor($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->sendCode(Callers::current(), $email->id)->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)))->reason);

        self::assertSame([], $this->mailbox->sent());
        self::assertSame([], $this->reported);
        self::assertSame(0, $this->factorRun($totp));
    }

    /**
     * With no sign-in in any other session of the Laravel session.
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

        $result = $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code));

        self::assertSame($this->bindingOf($user, self::PENDING, Purpose::SIGN_IN), $result->proof?->binding->toArray());
    }

    /**
     * The pending id survives activation.
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

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->reason);
        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code), Purpose::SIGN_IN)->isVerified());
    }

    /**
     * A sign-in code never answers a step-up, and the reverse.
     *
     * @return void
     */
    public function testACodesPurposeIsBound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$stepUp, $stepUpCode] = $this->sentCode($factor);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $stepUp, $stepUpCode), Purpose::SIGN_IN)->reason);
        self::assertSame(Purpose::STEP_UP, $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $stepUp, $stepUpCode))->proof?->binding->purpose);

        [$signIn, $signInCode] = $this->sentCode($factor, Purpose::SIGN_IN);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $signIn, $signInCode))->reason);
        $result = $this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $signIn, $signInCode), Purpose::SIGN_IN);

        self::assertSame(Purpose::SIGN_IN, $result->proof?->binding->purpose);
    }

    /**
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
     * The identity, application, session and purpose, on each route; the
     * store's own sign-in is the one named.
     *
     * @param  string  $route
     * @return void
     */
    #[DataProvider('routes')]
    public function testAProofsBindingHasAllFourParts(string $route): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();

        $result = $this->mfa()->verify(Callers::current(), $this->passingSubmission($user, $route));

        self::assertSame($this->bindingOf($user, self::SESSION, Purpose::STEP_UP), $result->proof?->binding->toArray());
        self::assertCount(1, $this->furtherProofs($user));
    }

    /**
     * When the store's current sign-in is not the pending id; everything rolls
     * back.
     *
     * @return void
     */
    public function testTheDefaultCompletionRefusesAnotherSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->pendingSession($user);

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->failureReported()->reason);
        self::assertSame([], $this->storedProofs($user));
    }

    /**
     * The guard's user is not served in its place.
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

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->sendCode(Callers::current(), $email->id)->reason);
        self::assertSame([], $this->reported);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->requestAssertion(Callers::current(), $factor->id)->reason);
    }

    /**
     * The resolver's exception is not caught, and nothing is counted.
     *
     * @return void
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, '000000'));
    }
}
