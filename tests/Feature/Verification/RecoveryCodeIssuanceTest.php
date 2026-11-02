<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FreshOnceGate;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Generating a recovery code set for the person the request serves needs a
 * session fresh enough for the operation that also reaches the level the
 * application sets for issuing them, checked before the codes are drawn and
 * again under the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeIssuanceTest extends TestCase
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
     * A fresh step-up that reaches the level is issued a set, once.
     *
     * @return void
     */
    public function testAFreshSessionAtTheLevelIsIssuedASet(): void
    {
        $user = $this->steppedUpPerson();

        self::assertCount(10, $this->mfa()->generateRecoveryCodes());
        self::assertSame(10, RecoveryCode::query()->whereNull('replaced_at')->count());
        self::assertTrue($user->isMfaEnabled());
    }

    /**
     * A session that is not fresh for the operation is refused, with nothing
     * drawn or replaced.
     *
     * @return void
     */
    public function testASessionNotFreshIsRefused(): void
    {
        $user = $this->steppedUpPerson();

        $this->recoveryCode($user);

        Carbon::setTestNow(now()->addHour());

        $this->assertRefused();
    }

    /**
     * A fresh session below the level is refused, with the same reason.
     *
     * @return void
     */
    public function testASessionBelowTheLevelIsRefused(): void
    {
        $user = $this->steppedUpPerson(['recovery_codes' => ['enabled' => true, 'level' => 'aal3']]);

        $this->recoveryCode($user);

        $this->assertRefused();
    }

    /**
     * The level is the application's: a lower one is met by less.
     *
     * @return void
     */
    public function testALowerLevelIsMetByLess(): void
    {
        $this->enableApplication([
            'recovery_codes' => ['enabled' => true, 'level' => 'aal1'],
            'freshness'      => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]],
        ]);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue($this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code))->isVerified());
        self::assertCount(10, $this->mfa()->generateRecoveryCodes());
    }

    /**
     * An email code is accepted without reaching the default level, so it is
     * refused even when fresh.
     *
     * @return void
     */
    public function testAnEmailStepUpDoesNotReachTheDefaultLevel(): void
    {
        $this->enableApplication(['freshness' => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]]]);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue($this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code))->isVerified());

        $this->assertRefused();
    }

    /**
     * A pending session is served nothing here, even one that allows every
     * action.
     *
     * @return void
     */
    public function testAPendingSessionIsServedNothing(): void
    {
        $user = $this->steppedUpPerson();

        $this->pendingSession($user, Requirement::none(), [PendingAction::LIST_FACTORS, PendingAction::SEND_CODE, PendingAction::VERIFY]);

        self::assertSame([], $this->mfa()->generateRecoveryCodes());
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * A person with no sign-in is refused, and so is nobody at all served
     * nothing.
     *
     * @return void
     */
    public function testNoSignInIsRefused(): void
    {
        self::assertSame([], $this->mfa()->generateRecoveryCodes());

        $user = $this->person();

        $this->totpFactor($user);
        $this->actingAs($user);

        $this->assertRefused();
    }

    /**
     * A session that stops being fresh after the first check is refused under
     * the lock, and the old set stays intact.
     *
     * @return void
     */
    public function testAGateFailingUnderTheLockKeepsTheOldSet(): void
    {
        $user = $this->steppedUpPerson();
        $old  = $this->recoveryCode($user);

        $gate = new FreshOnceGate;

        $this->container()->instance(FreshnessGate::class, $gate);

        $this->assertRefused();

        self::assertSame(2, $gate->reads);
        self::assertSame(10, RecoveryCode::query()->whereNull('replaced_at')->count());
        self::assertTrue($this->mfa()->verify(Submission::recoveryCode($old))->isVerified());
    }

    /**
     * A sign-in that changes under the generation is refused.
     *
     * @return void
     */
    public function testASignInThatChangesIsRefused(): void
    {
        $this->steppedUpPerson();

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        $this->assertRefused('The session is no longer the one the recovery codes were asked for on.');
    }

    /**
     * A person whose factor was stepped up with, on the application configured
     * for the operation, with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function steppedUpPerson(array $settings = []): TestUser
    {
        $this->enableApplication([
            'freshness' => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]],
            ...$settings,
        ]);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());

        return $user;
    }

    /**
     * Generating is refused as not fresh, leaving what was there.
     *
     * @param  ?string  $detail
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefused(?string $detail = null): void
    {
        $before = RecoveryCode::query()->whereNull('replaced_at')->count();

        try {
            $this->mfa()->generateRecoveryCodes();

            self::fail('Generating must be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
            self::assertSame($detail ?? $exception->getMessage(), $exception->getMessage());
        }

        self::assertSame($before, RecoveryCode::query()->whereNull('replaced_at')->count());
    }
}
