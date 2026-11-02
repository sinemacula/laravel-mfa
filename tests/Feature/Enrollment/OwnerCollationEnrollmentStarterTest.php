<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentGrant;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enrollment\GrantAuthority;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChange;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Two owners who differ only in case stay apart on a database whose collation
 * compares them as equal: what one does never reaches the other's factors or
 * enrolments, nor counts them as its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentService::class)]
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(GrantAuthority::class)]
#[CoversClass(EnrollmentGrant::class)]
#[CoversClass(EnrollmentRequest::class)]
#[CoversClass(EnrollmentStart::class)]
#[CoversClass(EnrollmentConfirmation::class)]
#[CoversClass(EnrollmentSettings::class)]
#[CoversClass(FactorChannel::class)]
#[CoversClass(FactorLabel::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(CodeNotSentException::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(SessionReevaluation::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(RequirementService::class)]
#[CoversClass(TotpDriver::class)]
#[CoversClass(TotpSettings::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(MfaManager::class)]
#[CoversClass(Evaluation::class)]
#[CoversClass(Combination::class)]
#[CoversClass(DefaultCombinationPolicy::class)]
#[CoversClass(FactorStateTransaction::class)]
#[CoversClass(FactorService::class)]
#[CoversClass(FactorChange::class)]
final class OwnerCollationEnrollmentStarterTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * Arrange the application, and compare the owner columns of the factors and
     * the enrolments as a case-insensitive collation does, on SQLite, where the
     * statement making a table can be read back and made again with it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $connection = DB::connection(StorageConnection::name());

        if ($connection->getDriverName() !== 'sqlite') {
            self::markTestSkipped('The collation is changed through SQLite\'s own schema.');
        }

        $this->arrangeVerification();

        foreach ([TableNames::of(TableNames::FACTORS), TableNames::of(TableNames::ENROLLMENTS)] as $table) {
            $statement = $connection->scalar('select sql from sqlite_master where type = ? and name = ?', ['table', $table]);

            self::assertIsString($statement);

            $connection->statement(sprintf('drop table "%s"', $table));
            $connection->statement(preg_replace('/"(authenticatable_type|authenticatable_id)" varchar not null/', '$0 collate nocase', $statement) ?? $statement);
        }
    }

    /**
     * A restart leaves another owner's pending factor and grant alone.
     *
     * @return void
     */
    public function testARestartLeavesAnotherOwnersEnrollmentAlone(): void
    {
        $user   = $this->reauthenticatedPerson();
        $theirs = $this->startedTotp();

        $this->handToAnotherOwner($user);
        $this->forgetReports();

        $mine = $this->startedTotp();

        self::assertSame(['EnrollmentStarted'], $this->reportedNames());
        self::assertSame(2, Enrollment::query()->count());
        self::assertTrue($this->rowOf($theirs)->exists);
        self::assertSame(2, Factor::query()->count());
        self::assertNotSame($theirs->factor?->id, $mine->factor?->id);
    }

    /**
     * A restart leaves another owner's grant alone even when its factor is
     * gone.
     *
     * @return void
     */
    public function testARestartLeavesAnotherOwnersOrphanedGrantAlone(): void
    {
        $user   = $this->reauthenticatedPerson();
        $theirs = $this->startedTotp();

        $this->handToAnotherOwner($user);

        Factor::query()->delete();

        $this->startedTotp();

        self::assertTrue($this->rowOf($theirs)->exists);
    }

    /**
     * Another owner's confirmed factor is not one's own, so it neither closes
     * the bootstrap path nor counts towards a limit.
     *
     * @return void
     */
    public function testAnotherOwnersConfirmedFactorIsNotOnesOwn(): void
    {
        $user = $this->bootstrapPerson();

        $this->totpFactor($user, ['application' => self::APPLICATION, 'authenticatable_type' => self::otherType($user)]);

        $start = $this->startedTotp();

        self::assertTrue($this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start))->isConfirmed());
    }

    /**
     * Another owner's factor cannot be renamed or made preferred, and choosing
     * one's own leaves another owner's preference where it is.
     *
     * @return void
     */
    public function testAnotherOwnersFactorIsOutOfReach(): void
    {
        $user   = $this->signedInPerson();
        $theirs = $this->totpFactor($user, ['application' => self::APPLICATION, 'authenticatable_type' => self::otherType($user), 'preferred' => true, 'label' => 'Theirs']);
        $mine   = $this->totpFactor($user, ['application' => self::APPLICATION]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->renameFactor($theirs->id, 'Mine now')->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->setPreferredFactor($theirs->id)->reason);
        self::assertTrue($this->mfa()->setPreferredFactor($mine->id)->factor?->preferred);

        $stored = Factor::query()->whereKey($theirs->id)->sole();

        self::assertTrue($stored->isPreferred());
        self::assertSame('Theirs', $stored->getLabel());
    }

    /**
     * Hand the enrolment under way to another owner.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function handToAnotherOwner(TestUser $user): void
    {
        $type = self::otherType($user);

        Factor::query()->update(['authenticatable_type' => $type]);
        Enrollment::query()->update(['authenticatable_type' => $type]);
    }

    /**
     * An owner type differing from the person's only in case.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return string
     */
    private static function otherType(TestUser $user): string
    {
        return strtoupper(ProofOwner::of($user)->type);
    }
}
