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
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;

/**
 * The statements each branch of an enrolment makes, read and written, with each
 * one named in a ledger beside its budget. Each person has signed in on the
 * application's declared first factor and proved it again or stepped up.
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
     * Starting a TOTP enrolment.
     *
     * @return void
     */
    public function testATotpStart(): void
    {
        $this->reauthenticatedPerson();

        // Reads (8): under the lock, the factors and the state (2); the
        // reauthentication's generation and its freshness (2); the first
        // factor's proofs (1); the pending enrolments, for those to discard and
        // the limit (2); the grant's generation (1).
        //
        // Writes (6): the address's slot (2) and the slot given back (1); the
        // lock (1); the pending factor and the enrolment (2).
        $start = $this->assertQueryBudget(8, 6, fn (): EnrollmentStart => $this->mfa()->startEnrollment(EnrollmentRequest::totp(self::ACCOUNT)));

        self::assertTrue($start->hasStarted());
    }

    /**
     * Starting a delivered enrolment, which sends the first code.
     *
     * @return void
     */
    public function testADeliveredStart(): void
    {
        $this->reauthenticatedPerson();

        // Reads (17): those of a TOTP start (8); the gateway's admission, its
        // factors, the enrolment, the enrolment's generation and the state (4);
        // the send's factors, the factor's open code, the destination's and the
        // identity's codes for their caps, and the destination's last code for
        // the restart (5).
        //
        // Writes (10): those of a TOTP start (6); the locks of the admission
        // and the send (2); the code, and the challenge on the enrolment (2).
        $start = $this->assertQueryBudget(17, 10, fn (): EnrollmentStart => $this->mfa()->startEnrollment(EnrollmentRequest::delivered('email', self::ADDRESS)));

        self::assertTrue($start->hasStarted());
    }

    /**
     * The sizes of a set, and the writes a first factor's confirmation makes
     * with each: the ten it makes anyway, and one for each code.
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
     * Confirming a first factor generates a set: the reads do not follow the
     * size of the set, and the writes follow it exactly, as the set is inserted
     * row by row.
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

        // Reads (12): under the lock, the factors, the enrolment, its
        // generation and the state (4); the proof's generation and the
        // session's proofs it must be accepted after (2); the issuance's proofs
        // and whether a factor is confirmed (2); under the set's lock, its
        // factors and state (2); the evaluation's proofs and the re-enrolment
        // obligation (2).
        //
        // Writes (10, and one for each code): the address's slot, by the update
        // alone (1); the lock (1); the step's compare-and-set, the factor
        // confirmed and the enrolment deleted (3); the obligation ended (1);
        // the set's lock, the old set replaced and the new one's generation
        // (3); and the slot given back (1).
        $confirmation = $this->assertQueryBudget(12, $writes, fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment($grant, $code));

        self::assertTrue($confirmation->isConfirmed());
        self::assertCount($count, $confirmation->recoveryCodes);
    }

    /**
     * Confirming a later factor generates no set.
     *
     * @return void
     */
    public function testALaterFactorConfirmation(): void
    {
        $this->steppedUpPerson();

        $start = $this->startedTotp();
        $grant = $this->grantOf($start);
        $code  = $this->appCode($start);

        // Reads (7): under the lock, the factors, the enrolment, its generation
        // and the state (4); the proof's generation (1); the evaluation's
        // proofs and the re-enrolment obligation (2).
        //
        // Writes (7): the address's slot, by the update alone (1); the lock
        // (1); the step's compare-and-set, the factor confirmed and the
        // enrolment deleted (3); the obligation ended (1); and the slot given
        // back (1).
        $confirmation = $this->assertQueryBudget(7, 7, fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment($grant, $code));

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame([], $confirmation->recoveryCodes);
    }

    /**
     * A wrong code counts on the enrolment and keeps the address's slot.
     *
     * @return void
     */
    public function testAWrongCodeConfirmation(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $grant = $this->grantOf($start);
        $code  = $this->wrongCode($start);

        // Reads (4): under the lock, the factors, the enrolment, its generation
        // and the state.
        //
        // Writes (3): the address's slot, by the update alone (1); the lock
        // (1); the attempt counted on the enrolment (1).
        $confirmation = $this->assertQueryBudget(4, 3, fn (): EnrollmentConfirmation => $this->mfa()->confirmEnrollment($grant, $code));

        self::assertSame(FailureReason::INVALID_CODE, $confirmation->reason);
    }
}
