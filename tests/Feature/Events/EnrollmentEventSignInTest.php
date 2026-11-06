<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EnrollmentStarted;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\RecordingEventContextResolver;
use Tests\TestCase;

/**
 * Every event of a bootstrap enrolment names the pending session's sign-in it
 * was bound to, not the sign-in the proof store holds for the identity: its
 * start, a code resent, its confirmation with the recovery codes issued with
 * the first factor, its expiry, a failure, and its abandonment, whether by the
 * cap or by a cancel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDispatcher::class)]
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentService::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
final class EnrollmentEventSignInTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * Arrange the application and bind the recording resolver.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->container()->instance(EventContextResolver::class, new RecordingEventContextResolver);
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
     * A bootstrap enrolment's start and confirmation, and the recovery codes
     * issued with the first factor, name the pending session's sign-in.
     *
     * @return void
     */
    public function testABootstrapEnrollmentNamesThePendingSignIn(): void
    {
        $user  = $this->bootstrapOnAnotherSignIn();
        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertTrue($confirmation->isConfirmed());
        self::assertCount(10, $confirmation->recoveryCodes);
        self::assertSame([self::PENDING], $this->signInsOf(EnrollmentStarted::class));
        self::assertSame([self::PENDING], $this->signInsOf(VerificationPassed::class));
        self::assertSame([self::PENDING], $this->signInsOf(FactorConfirmed::class));
        self::assertSame([self::PENDING], $this->signInsOf(RecoveryCodesGenerated::class));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * A bootstrap enrolment that expired names the pending session's sign-in,
     * on the expiry and on the failure it reports.
     *
     * @return void
     */
    public function testAnExpiredBootstrapEnrollmentNamesThePendingSignIn(): void
    {
        $user  = $this->bootstrapOnAnotherSignIn();
        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        Enrollment::query()->update(['expires_at' => CarbonImmutable::now()->subSecond()]);

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertSame([self::PENDING], $this->signInsOf(EnrollmentExpired::class));
        self::assertSame([self::PENDING], $this->signInsOf(VerificationFailed::class));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * A wrong code on a bootstrap enrolment names the pending session's sign-in
     * on its failure and on the abandonment the cap brings.
     *
     * @return void
     */
    public function testAnAbandonedBootstrapEnrollmentNamesThePendingSignIn(): void
    {
        config()->set('mfa.enrollment.max_attempts', 1);

        $user  = $this->bootstrapOnAnotherSignIn();
        $start = $this->startedTotp();

        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->wrongCode($start))->abandoned);
        self::assertSame([self::PENDING], $this->signInsOf(VerificationFailed::class));
        self::assertSame([self::PENDING], $this->signInsOf(EnrollmentAbandoned::class));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * A code resent for a bootstrap enrolment, and its cancel, name the pending
     * session's sign-in.
     *
     * @return void
     */
    public function testAResentCodeAndACancelNameThePendingSignIn(): void
    {
        $user  = $this->bootstrapOnAnotherSignIn();
        $start = $this->startedEmail();

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        self::assertNotNull($this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start))->challengeId);
        self::assertTrue($this->mfa()->cancelEnrollment(Callers::current(), $this->grantOf($start)));
        self::assertSame([self::PENDING, self::PENDING], $this->signInsOf(CodeSent::class));
        self::assertSame([self::PENDING], $this->signInsOf(EnrollmentAbandoned::class));
        self::assertSame(self::SESSION, $this->currentSignIn($user));
    }

    /**
     * A person on a bootstrap session, whose active sign-in is the one the
     * proof store holds, with a completion that takes a proof bound to the
     * pending session without asking the store.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function bootstrapOnAnotherSignIn(): TestUser
    {
        $this->enableApplication(['bootstrap' => ['enabled' => true, 'types' => ['totp', 'email']]]);

        $user = $this->person();

        $this->beginSignIn($user);
        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);
        $this->container()->instance(PendingCompletion::class, new CheckingCompletion(self::PENDING));

        return $user;
    }

    /**
     * The identity's current sign-in, as the proof store holds it.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return ?string
     */
    private function currentSignIn(TestUser $user): ?string
    {
        return $this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION);
    }

    /**
     * The sign-ins the events of the class reported name, in order.
     *
     * @param  class-string<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $class
     * @return list<int|string|null>
     */
    private function signInsOf(string $class): array
    {
        return RecordingEventContextResolver::signInsOf($this->reported, $class);
    }
}
