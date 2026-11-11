<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use SineMacula\Laravel\Mfa\Events\FactorRenamed;
use SineMacula\Laravel\Mfa\Events\PreferredFactorChanged;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Seams\RecordingEventContextResolver;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Events name the sign-in an operation was bound to, even once the proof store
 * has moved on; operations that capture none name none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDispatcher::class)]
#[CoversClass(EventSubject::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(VerificationService::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
final class EventSignInTest extends TestCase
{
    use ArrangesVerification;

    /** @var string Sign-in the proof store moves on to. */
    private const string LATER = 'sign-in-b';

    /** @var \Tests\Fixtures\Seams\RecordingEventContextResolver Records what it is handed. */
    private RecordingEventContextResolver $resolver;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->resolver = new RecordingEventContextResolver;

        $this->container()->instance(EventContextResolver::class, $this->resolver);
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
     * @return void
     */
    public function testAPendingVerificationNamesThePendingSignIn(): void
    {
        $user   = $this->pendingPerson();
        $factor = $this->totpFactor($user);

        self::assertFalse($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, '000000'))->isVerified());
        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertSame([self::PENDING], $this->signInsOf(VerificationFailed::class));
        self::assertSame([self::PENDING], $this->signInsOf(VerificationPassed::class));
        self::assertSame([self::PENDING], array_values(array_unique($this->resolver->signIns())));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * @return void
     */
    public function testAnActiveVerificationNamesItsSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertSame([self::SESSION], $this->signInsOf(VerificationPassed::class));
    }

    /**
     * @return void
     */
    public function testACodeSentOnAPendingSessionNamesThePendingSignIn(): void
    {
        $user = $this->pendingPerson();

        $this->sentCode($this->emailFactor($user));

        self::assertSame([self::PENDING], $this->signInsOf(CodeSent::class));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * The proof store has moved on by the time the refusal is reported.
     *
     * @return void
     */
    public function testAFactorRefusedAfterTheBindingNamesTheActiveSignIn(): void
    {
        $user   = $this->signedInPerson();
        $theirs = $this->totpFactor($this->person('other@example.test'));

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class), 1, self::LATER));

        $result = $this->mfa()->verify(Callers::current(), Submission::factor($theirs->id, AuthenticatorApp::code($theirs)));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertNull($this->failureReported()->factor);
        self::assertSame([self::SESSION], $this->signInsOf(VerificationFailed::class));
        self::assertSame(self::LATER, $this->currentSignIn($user));
    }

    /**
     * @return void
     */
    public function testARecoveryCodeRedeemedOnAPendingSessionNamesThePendingSignIn(): void
    {
        $user = $this->pendingPerson();

        $this->totpFactor($user);

        $code = $this->recoveryCode($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::recoveryCode($code))->isVerified());
        self::assertSame([self::PENDING], $this->signInsOf(RecoveryCodeUsed::class));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * @return void
     */
    public function testRecoveryCodesGeneratedForAnActiveCallerNameItsSignIn(): void
    {
        $this->enableApplication([
            'freshness' => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]],
        ]);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertTrue($this->mfa()->generateRecoveryCodes(Callers::current())->wasGenerated());
        self::assertSame([self::SESSION], $this->signInsOf(RecoveryCodesGenerated::class));
    }

    /**
     * Neither captures a sign-in, though the caller is on an active one.
     *
     * @return void
     */
    public function testARenameAndAPreferredFactorNameNoSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['application' => self::APPLICATION, 'label' => 'Old']);

        self::assertTrue($this->mfa()->renameFactor(Callers::current(), $factor->id, 'New')->wasMade());
        self::assertTrue($this->mfa()->setPreferredFactor(Callers::current(), $factor->id)->wasMade());
        self::assertSame([null], $this->signInsOf(FactorRenamed::class));
        self::assertSame([null], $this->signInsOf(PreferredFactorChanged::class));
    }

    /**
     * @return void
     */
    public function testAnOperatorsActionNamesNoSignIn(): void
    {
        $user   = $this->person();
        $factor = $this->totpFactor($user);

        $factor->update(['locked_until' => Carbon::now()->addHour()]);

        self::assertTrue($this->mfa()->unlockFactor($user, $factor->id, new Actor('admin', '9')));

        self::assertNotSame([], $this->resolver->subjects);
        self::assertSame([null], array_values(array_unique($this->resolver->signIns())));
    }

    /**
     * The completion takes the pending-bound proof without asking the store.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function pendingPerson(): TestUser
    {
        $user = $this->person();

        $this->beginSignIn($user);
        $this->pendingSession($user);
        $this->container()->instance(PendingCompletion::class, new CheckingCompletion(self::PENDING));

        return $user;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return ?string
     */
    private function currentSignIn(TestUser $user): ?string
    {
        return $this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION);
    }

    /**
     * Sign-ins named by the reported events of the class, in order.
     *
     * @param  class-string<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $class
     * @return list<int|string|null>
     */
    private function signInsOf(string $class): array
    {
        return RecordingEventContextResolver::signInsOf($this->reported, $class);
    }
}
