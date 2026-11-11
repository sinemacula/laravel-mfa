<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * TOTP end to end through the shipped driver and the session proof store. Time
 * is frozen mid-step so no assertion straddles a step boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(TotpDriver::class)]
final class TotpLifecycleTest extends TestCase
{
    use RefreshDatabase;

    /** @var string Matches no step of the window at the frozen time. */
    private const string WRONG_CODE = '000000';

    /** @var int 15 seconds into time step 60000000. */
    private const int NOW = 1800000015;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(CarbonImmutable::createFromTimestamp(self::NOW));

        config()->set('mfa.applications.web', ['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);
    }

    /**
     * @return void
     */
    public function testSuccessfulVerificationRecordsTheAcceptedStep(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        self::assertSame(60000000, $factor->refresh()->getLastAcceptedStep());
    }

    /**
     * A replay counts as a failed attempt.
     *
     * @return void
     */
    public function testTheSameCodeIsRefusedAtTheSecondVerification(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isVerified());

        Event::fake([VerificationFailed::class]);

        self::assertSame(FailureReason::REPLAYED, Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->reason);
        self::assertSame(1, $factor->refresh()->getConsecutiveFailures());

        Event::assertDispatched(
            VerificationFailed::class,
            static fn (VerificationFailed $event): bool => $event->reason === FailureReason::REPLAYED,
        );
    }

    /**
     * @return void
     */
    public function testACodeForAnEarlierStepIsRefusedAfterALaterOne(): void
    {
        [, $factor] = $this->enrollTotp();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, -1)))->isFailed());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, 1)))->isVerified());
    }

    /**
     * @return void
     */
    public function testTheConfirmingCodeIsRefusedAtTheNextVerification(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        $driver = Mfa::driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);
        self::assertSame(CodeCheck::ACCEPTED, $driver->confirm($factor, $code, new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::ENROLLMENT)));
        self::assertSame(60000000, $factor->refresh()->getLastAcceptedStep());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isFailed());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, 1)))->isVerified());
    }

    /**
     * @return void
     */
    public function testSuccessfulVerificationIsVerified(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isVerified());
    }

    /**
     * @return void
     */
    public function testSuccessfulVerificationRecordsAProof(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        $proofs = Mfa::proofs(Callers::current());

        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame($factor->getKey(), $proofs[0]->reference);
    }

    /**
     * @return void
     */
    public function testSuccessfulVerificationStampsFactorLastUse(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        $factor->refresh();

        self::assertNotNull($factor->getLastUsedAt());
        self::assertSame(0, $factor->getConsecutiveFailures());
    }

    /**
     * @return void
     */
    public function testSuccessfulVerificationDispatchesVerifiedEvent(): void
    {
        Event::fake([VerificationPassed::class]);

        [$user, $factor, $code] = $this->enrollTotp();

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        $key = $user->getKey();

        Event::assertDispatched(VerificationPassed::class, static function (VerificationPassed $event) use ($key, $factor): bool {
            self::assertSame($factor->id, $event->factor?->id);
            self::assertSame('totp', $event->type);
            self::assertEquals($key, $event->context['identity_id']);

            return true;
        });
    }

    /**
     * @return void
     */
    public function testFailedVerificationIncrementsAttemptsAndFiresFailureEvent(): void
    {
        Event::fake([VerificationFailed::class]);

        [, $factor] = $this->enrollTotp();

        $result = Mfa::verify(Callers::current(), Submission::factor($factor->id, self::WRONG_CODE));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);

        $factor->refresh();
        self::assertSame(1, $factor->getConsecutiveFailures());
        self::assertNull($factor->getLastUsedAt());

        Event::assertDispatched(
            VerificationFailed::class,
            static fn (VerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * @return void
     */
    public function testThresholdCrossingRecordsConfiguredAttemptsCount(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        self::assertSame(3, $factor->getConsecutiveFailures());
    }

    /**
     * @return void
     */
    public function testThresholdCrossingLocksTheFactorUntilAFutureTime(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        $lockout = $this->lockoutOf($factor);

        self::assertNotNull($lockout);
        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertTrue($lockout->until?->isFuture());
    }

    /**
     * @return void
     */
    public function testVerifyingAfterLockoutFails(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, self::WRONG_CODE))->reason);
    }

    /**
     * @return void
     */
    public function testVerifyingAfterLockoutDispatchesLockedFailure(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        Event::fake([VerificationFailed::class]);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, self::WRONG_CODE));

        Event::assertDispatched(
            VerificationFailed::class,
            static fn (VerificationFailed $event): bool => $event->reason === FailureReason::LOCKED,
        );
    }

    /**
     * A resend endpoint must never act as a free unlock.
     *
     * @return void
     */
    public function testAskingForACodePreservesAttemptsAfterLockout(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        Mfa::sendCode(Callers::current(), $factor->id);

        $factor->refresh();

        self::assertSame(3, $factor->getConsecutiveFailures());
    }

    /**
     * @return void
     */
    public function testAskingForACodePreservesTheLockoutEndAfterLockout(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        $lockedUntilBefore = $this->lockoutOf($factor)?->until;
        self::assertNotNull($lockedUntilBefore);

        Mfa::sendCode(Callers::current(), $factor->id);

        $lockedUntilAfter = $this->lockoutOf($factor)?->until;
        self::assertNotNull($lockedUntilAfter);
        self::assertSame(
            $lockedUntilBefore->getTimestamp(),
            $lockedUntilAfter->getTimestamp(),
        );
    }

    /**
     * @return void
     */
    public function testAskingForACodeKeepsFactorLockedAfterLockout(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        Mfa::sendCode(Callers::current(), $factor->id);

        self::assertNotNull($this->lockoutOf($factor));
    }

    /**
     * A signed-in user, their confirmed TOTP factor and its current code.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: string}
     */
    private function enrollTotp(): array
    {
        $user = TestUser::create([
            'email'       => 'totp@example.test',
            'mfa_enabled' => true,
        ]);

        Auth::login($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'status'               => 'confirmed',
        ]);

        return [$user, $factor, AuthenticatorApp::code($factor)];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lockoutOf(Factor $factor): ?Lockout
    {
        $user = TestUser::query()->findOrFail($factor->authenticatable_id);

        return $this->container()->make(AttemptService::class)->lockout($user, $factor);
    }

    /**
     * A TOTP factor locked out by failed attempts.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function enrollAndBurnAttempts(): Factor
    {
        [, $factor] = $this->enrollTotp();

        config()->set('mfa.attempts.factor_limit', 3);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, self::WRONG_CODE));
        Mfa::verify(Callers::current(), Submission::factor($factor->id, self::WRONG_CODE));
        Mfa::verify(Callers::current(), Submission::factor($factor->id, self::WRONG_CODE));

        $factor->refresh();

        return $factor;
    }
}
