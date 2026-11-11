<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;

/**
 * Each person signed in on the declared first factor and then reauthenticated
 * or stepped up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(AttemptService::class)]
#[CoversClass(AttemptStore::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(DeliveredCodes::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(TotpDriver::class)]
#[CoversClass(EmailDriver::class)]
final class EnrollmentQueryBudgetTest extends PerformanceContractTestCase
{
    use ArrangesEnrollment;

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
    public function testATotpStart(): void
    {
        $this->reauthenticatedPerson();

        // Reads: factors and state 2, reauthentication 2, proofs 1, pending
        // enrolments 2, grant 1.
        // Writes: slot 2, returned 1, lock 1, pending factor and enrolment 2.
        $start = $this->assertQueryBudget(8, 6, fn (): EnrollmentStart => $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT)));

        self::assertTrue($start->hasStarted());
    }

    /**
     * @return void
     */
    public function testADeliveredStart(): void
    {
        $this->reauthenticatedPerson();

        // Reads: TOTP start 8, admission 4, send with its caps and restart 5.
        // Writes: TOTP start 6, admission and send locks 2, code and challenge
        // 2.
        $caller = Callers::current();
        $start  = $this->assertQueryBudget(17, 10, fn (): EnrollmentStart => $this->mfa()->startEnrollment($caller, EnrollmentRequest::delivered('email', self::ADDRESS)));

        self::assertTrue($start->hasStarted());
    }

    /**
     * Set size and the confirmation's writes: ten plus one per code.
     *
     * @return iterable<string, array{int, int}>
     */
    public static function recoverySetSizes(): iterable
    {
        yield from [
            'the default set' => [10, 20],
            'a smaller set'   => [6, 16],
        ];
    }

    /**
     * Writes follow the set size exactly, as the set is inserted row by row.
     *
     * @param  int  $count
     * @param  int  $writes
     * @return void
     */
    #[DataProvider('recoverySetSizes')]
    public function testAFirstFactorConfirmation(int $count, int $writes): void
    {
        config()->set('mfa.recovery_codes.count', $count);

        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $grant = $this->grantOf($start);
        $code  = $this->appCode($start);

        // Reads: lock 4, proof 2, issuance 2, set's lock 2, evaluation 2.
        // Writes: slot 1, lock 1, step 3, obligation 1, set 3, returned 1, and
        // one per code.
        $confirmation = $this->assertQueryBudget(12, $writes, fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code));

        self::assertTrue($confirmation->isConfirmed());
        self::assertCount($count, $confirmation->recoveryCodes);
    }

    /**
     * @return void
     */
    public function testALaterFactorConfirmation(): void
    {
        $this->steppedUpPerson();

        $start = $this->startedTotp();
        $grant = $this->grantOf($start);
        $code  = $this->appCode($start);

        // Reads: lock 4, proof 1, evaluation 2.
        // Writes: slot 1, lock 1, step 3, obligation 1, returned 1.
        $confirmation = $this->assertQueryBudget(7, 7, fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code));

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame([], $confirmation->recoveryCodes);
    }

    /**
     * @return void
     */
    public function testAWrongCodeConfirmation(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $grant = $this->grantOf($start);
        $code  = $this->wrongCode($start);

        // Reads: lock 4. Writes: slot 1, lock 1, attempt 1.
        $confirmation = $this->assertQueryBudget(4, 3, fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code));

        self::assertSame(FailureReason::INVALID_CODE, $confirmation->reason);
    }
}
