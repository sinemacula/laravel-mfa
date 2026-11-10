<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersContract;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeCountersTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The challenge counters wiring kit proves the package's own challenge gateway,
 * which counts every outcome inside its transaction, and rejects a challenge
 * path that counts nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeCountersContract::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
final class ChallengeCountersContractTest extends TestCase
{
    use ArrangesEmailChallenges, ChallengeCountersTests;

    /** @var \Tests\Fixtures\Identities\TestUser The person challenged. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's email factor. */
    private Factor $factor;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The codes sent. */
    private FakeEmailSender $mailbox;

    /** @var ?string The challenge failed answers are given to, once sent. */
    private ?string $challenge = null;

    /** @var ?string The hook, `admit` or `report`, that swallows the counters' refusal, if any. */
    private ?string $swallows = null;

    /** @var ?string The hook, `admit` or `report`, that calls the counters in a transaction of its own, if any. */
    private ?string $ownTransaction = null;

    /** @var bool Whether the admission hook admits anything it is asked about. */
    private bool $admitsAnything = false;

    /**
     * Sign a person in with an email factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        [$this->user, $this->factor, $this->mailbox] = $this->arrangeEmailChallenges();
    }

    /**
     * The kit rejects a pending factor that holds a live enrolment as one with
     * none, as it would a gateway's admission of it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAFactorAnEnrollmentChallengeWouldAdmit(): void
    {
        $pending = $this->pendingFactor();
        $binding = $this->countedBinding();

        $this->enroll($pending, $binding);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A pending factor with no live enrolment must not be challenged.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $pending, $binding, $this->challengeAdmission(), $this->challengeReport());
    }

    /**
     * The kit rejects a factor given as confirmed that an enrolment challenge
     * would admit, even when the pending factor given is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAConfirmedFactorAnEnrollmentChallengeWouldAdmit(): void
    {
        $admitted = $this->pendingFactor();
        $binding  = $this->countedBinding();

        $this->enroll($admitted, $binding);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A confirmed factor must not be challenged for enrolling.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($admitted, $this->pendingFactor(), $binding, $this->challengeAdmission(), $this->challengeReport());
    }

    /**
     * The kit rejects an enrolment challenge whose report changes the factor's
     * count, though not the identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeThatChargesTheFactor(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s failed outcome must change no factor\'s count.');

        $report = $this->hasChargedTheFactor(...);

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $report);
    }

    /**
     * The kit rejects an enrolment challenge whose report changes the
     * identity's count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeThatChargesTheIdentity(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s failed outcome must change no identity\'s count.');

        $report = $this->hasChargedTheIdentity(...);

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $report);
    }

    /**
     * The kit rejects an enrolment challenge whose passed outcome resets the
     * counts, which it raises first so the reset shows.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentSuccessThatResetsTheCounts(): void
    {
        $factor    = $this->factor;
        $resetting = static function (EloquentFactor&Model $counted, ProofBinding $binding, bool $passed) use ($factor): bool {
            if ($passed) {
                WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->update([$factor->getConsecutiveFailuresName() => 0]);
            }

            return true;
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s passed outcome must change no factor\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $resetting);
    }

    /**
     * The kit rejects an enrolment challenge whose failed outcome alone is
     * counted against the factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentFailureThatChargesTheFactor(): void
    {
        $charging = fn (EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): bool => $passed || $this->hasChargedTheFactor($factor);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s failed outcome must change no factor\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $charging);
    }

    /**
     * The kit rejects an enrolment challenge whose passed outcome resets the
     * identity's count, which it raises first so the reset shows.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentSuccessThatResetsTheIdentity(): void
    {
        $resetting = static function (EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): bool {
            if ($passed) {
                IdentityState::query()
                    ->where('authenticatable_type', $binding->identityType)
                    ->where('authenticatable_id', $binding->identityKey)
                    ->update(['consecutive_failures' => 0]);
            }

            return true;
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s passed outcome must change no identity\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $resetting);
    }

    /**
     * The kit rejects an enrolment challenge whose failed outcome is counted
     * and whose passed outcome takes the count back, though the two cancel out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeWhoseOutcomesCancelOut(): void
    {
        $factor       = $this->factor;
        $compensating = static fn (EloquentFactor&Model $counted, ProofBinding $binding, bool $passed): bool => WriteConnection::query($factor->newQuery())
            ->whereKey($factor->getKey())
            ->increment($factor->getConsecutiveFailuresName(), $passed ? -1 : 1) > 0;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s failed outcome must change no factor\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $compensating);
    }

    /**
     * The kit rejects an enrolment challenge whose report counts only once the
     * transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeCountedOnCommit(): void
    {
        $factor   = $this->factor;
        $deferred = static function (EloquentFactor&Model $counted, ProofBinding $binding, bool $passed) use ($factor): bool {
            DB::connection(StorageConnection::name())->afterCommit(static function () use ($factor): void {
                WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->increment($factor->getConsecutiveFailuresName());
            });

            return true;
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s outcome must change no factor\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $deferred);
    }

    /**
     * The kit rejects an enrolment challenge whose report counts against the
     * identity only once the transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeCountedAgainstTheIdentityOnCommit(): void
    {
        $deferred = function (EloquentFactor&Model $factor, ProofBinding $binding): bool {
            DB::connection(StorageConnection::name())->afterCommit(fn (): bool => $this->hasChargedTheIdentity($factor, $binding));

            return true;
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s outcome must change no identity\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->factor, $this->pendingFactor(), $this->countedBinding(), $this->challengeAdmission(), $deferred);
    }

    /**
     * The kit rejects a challenge path that counts nothing.
     *
     * @return void
     */
    public function testRejectsAPathThatCountsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertAFailedChallengeIsCounted($this->factor, static function (): void {
            // A path that checks its own code and never reports the outcome.
        });
    }

    /**
     * The kit rejects a challenge path that counts in a transaction of its own,
     * committed whatever becomes of the change the challenge is part of.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatCommitsItsCountEarly(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertARolledBackChallengeCountsNothing($this->factor, function (): void {
            $this->countAFailure();
            DB::connection(StorageConnection::name())->commit();
        });
    }

    /**
     * A challenge path that fails leaves the kit's change rolled back, and its
     * failure propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingPathIsRolledBack(): void
    {
        $connection = DB::connection(StorageConnection::name());
        $level      = $connection->transactionLevel();
        $failure    = new \LogicException('The challenge path failed.');

        try {
            ChallengeCountersContract::assertARolledBackChallengeCountsNothing($this->factor, static function () use ($failure): void {
                throw $failure;
            });
            self::fail('The path\'s failure was expected to propagate.');
        } catch (\LogicException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($level, $connection->transactionLevel());
    }

    /**
     * The kit rejects a challenge path that challenges a disabled factor.
     *
     * @return void
     */
    public function testRejectsAPathThatChallengesADisabledFactor(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertADisabledFactorIsNotChallenged($this->factor, $this->countAFailure(...));
    }

    /**
     * The kit rejects an admission made in a transaction of the path's own,
     * though its report is sound.
     *
     * @return void
     */
    public function testRejectsAnAdmissionInATransactionOfItsOwn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to admit a challenge outside the caller\'s transaction.');

        $this->ownTransaction = 'admit';

        ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction($this->factor, $this->countedBinding(), $this->challengeAdmission(), $this->challengeReport());
    }

    /**
     * The kit rejects a report made in a transaction of the path's own, though
     * its admission is sound.
     *
     * @return void
     */
    public function testRejectsAReportInATransactionOfItsOwn(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to report a challenge outside the caller\'s transaction.');

        $this->ownTransaction = 'report';

        ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction($this->factor, $this->countedBinding(), $this->challengeAdmission(), $this->challengeReport());
    }

    /**
     * The kit rejects a report that swallows the counters' refusal.
     *
     * @return void
     */
    public function testRejectsAReportThatSwallowsTheRefusal(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to report a challenge outside the caller\'s transaction.');

        $this->swallows = 'report';

        ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction($this->factor, $this->countedBinding(), $this->challengeAdmission(), $this->challengeReport());
    }

    /**
     * The kit refuses to make the check inside a transaction, where sound calls
     * would not be refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsACheckMadeInsideATransaction(): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The check must be made outside any transaction on the storage connection.');

        try {
            ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction($this->factor, $this->countedBinding(), $this->challengeAdmission(), $this->challengeReport());
        } finally {
            $connection->rollBack();
        }
    }

    /**
     * The kit rejects a path that admits nothing, even the identity's own
     * binding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatAdmitsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A challenge of the identity\'s own factor under its own binding must be admitted.');

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            static fn (): bool => false,
            $this->challengeReport(),
        );
    }

    /**
     * The kit rejects a path that admits a binding of another identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatAdmitsAnotherIdentity(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A binding of another identity must not be admitted.');

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            static fn (): bool => true,
            $this->challengeReport(),
        );
    }

    /**
     * The kit rejects a path that takes a report under a binding of another
     * identity without refusing it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatTakesAReportForAnotherIdentity(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A report under a binding of another identity must be refused.');

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            $this->challengeAdmission(),
            static fn (): bool => true,
        );
    }

    /**
     * The kit accepts a path that refuses a report under a binding of another
     * identity by answering `false`, counting nothing, as an adapter whose
     * contract refuses by value does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAcceptsAReportRefusedByValue(): void
    {
        $report = $this->challengeReport();

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            $this->challengeAdmission(),
            static function (EloquentFactor&Model $factor, ProofBinding $binding, bool $passed) use ($report): bool {
                try {
                    return $report($factor, $binding, $passed);
                } catch (OperationRefusedException) {
                    return false;
                }
            },
        );
    }

    /**
     * Each count a refused report under a binding of another identity must
     * leave alone.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function chargedCounts(): iterable
    {
        yield 'the factor\'s' => ['factor', 'A report under a binding of another identity must change no factor\'s count.'];
        yield 'the identity\'s' => ['identity', 'A report under a binding of another identity must change no identity\'s count.'];
        yield 'the other identity\'s' => ['other', 'A report under a binding of another identity must count nothing against it.'];
    }

    /**
     * The kit rejects a path that refuses a report under a binding of another
     * identity only once it has counted it.
     *
     * @param  string  $charged
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('chargedCounts')]
    public function testRejectsAPathThatCountsAReportForAnotherIdentity(string $charged, string $message): void
    {
        $charge = match ($charged) {
            'factor'   => $this->hasChargedTheFactor(...),
            'identity' => $this->hasChargedTheIdentity(...),
            default    => static fn (EloquentFactor&Model $factor, ProofBinding $binding): bool => IdentityState::query()
                ->create(['authenticatable_type' => $binding->identityType, 'authenticatable_id' => $binding->identityKey, 'consecutive_failures' => 1])
                ->exists,
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage($message);

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            $this->challengeAdmission(),
            static fn (EloquentFactor&Model $factor, ProofBinding $binding): bool => !$charge($factor, $binding),
        );
    }

    /**
     * The kit's tests hand the contract the test case's own admission hook, so
     * one that swallows the counters' refusal fails them.
     *
     * @return void
     */
    public function testTheKitCallsTheAdmissionHook(): void
    {
        $this->swallows = 'admit';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to admit a challenge outside the caller\'s transaction.');

        $this->testChallengeCountersNeedTheCallersTransaction();
    }

    /**
     * The kit's tests hand the contract the test case's own report hook, so one
     * that swallows the counters' refusal fails them.
     *
     * @return void
     */
    public function testTheKitCallsTheReportHook(): void
    {
        $this->swallows = 'report';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The path must refuse to report a challenge outside the caller\'s transaction.');

        $this->testChallengeCountersNeedTheCallersTransaction();
    }

    /**
     * The kit's binding and enrolment tests hand the contract the test case's
     * own hooks too, so a path that admits anything fails them.
     *
     * @return void
     */
    public function testTheKitHandsEveryCheckTheHooks(): void
    {
        $this->admitsAnything = true;

        self::rejects(fn () => $this->testChallengeCountersRefuseABindingOfAnotherIdentity());
        self::rejects(fn () => $this->testChallengeCountersKeepAnEnrollmentChallengeApart());
    }

    /**
     * The kit rejects a challenge path that counts only once the caller's
     * transaction commits, and leaves that transaction rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatCountsAfterTheCallerCommits(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAFailureIsCountedBeforeTheCallerCommits($this->factor, function (): void {
            DB::connection(StorageConnection::name())->afterCommit($this->countAFailure(...));
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, $this->storedFailures());
    }

    /**
     * The kit rejects a challenge path that commits the caller's transaction to
     * count in it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatCommitsTheCallersTransaction(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAFailureIsCountedBeforeTheCallerCommits($this->factor, function (): void {
            $this->countAFailure();
            DB::connection(StorageConnection::name())->commit();
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * The kit rejects a challenge path that ends the caller's nested
     * transaction early to count in the outer one, and rolls both back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatEscapesANestedTransaction(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertANestedRollbackCountsNothing($this->factor, function (): void {
            DB::connection(StorageConnection::name())->commit();
            $this->countAFailure();
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, $this->storedFailures());
    }

    /**
     * The kit rejects a challenge path that swaps the caller's nested
     * transaction for one of its own, so its count lands in the outer one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatSwapsANestedTransaction(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertANestedRollbackCountsNothing($this->factor, function (): void {
            $connection = DB::connection(StorageConnection::name());

            $connection->commit();
            $this->countAFailure();
            $connection->beginTransaction();
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * The kit rejects a challenge path that counts nothing, so the identity is
     * never locked, and puts the limits back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatNeverLocksTheIdentity(): void
    {
        $limits = config('mfa.attempts');

        $binding = $this->emailBinding($this->user);

        self::rejects(fn () => ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $binding, static function (): void {
            // A path that checks its own code and never reports the outcome.
        }));

        self::assertSame($limits, config('mfa.attempts'));
    }

    /**
     * The kit rejects a challenge path that locks the identity at once.
     *
     * @return void
     */
    public function testRejectsAPathThatLocksTheIdentityEarly(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), function (): void {
            $this->failChallenge();
            $this->failChallenge();
        }));
    }

    /**
     * The kit rejects a challenge path that goes on counting against the factor
     * once the identity is locked.
     *
     * @return void
     */
    public function testRejectsAPathThatCountsALockedIdentity(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), function (): void {
            $this->failChallenge();
            $this->countAFailure();
        }));
    }

    /**
     * The kit puts the attempt limits back after the lockout check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockoutCheckPutsTheLimitsBack(): void
    {
        $limits = config('mfa.attempts');

        ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), $this->failChallenge(...));

        self::assertSame($limits, config('mfa.attempts'));
    }

    /**
     * The kit sets the factor's limit above the identity's for the lockout
     * check, so a host's limit on factors at or below it does not lock the
     * factor first, and puts the host's limit back after.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockoutCheckHoldsTheFactorsLimitAboveTheIdentitys(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), $this->failChallenge(...));

        self::assertSame(1, config('mfa.attempts.factor_limit'));
    }

    /**
     * The kit refuses an other identity that is the counted one, whose binding
     * the counters would rightly admit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnOtherIdentityThatIsTheCountedOne(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The other identity must not be the counted one.');

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->user,
            $this->challengeAdmission(),
            $this->challengeReport(),
        );
    }

    /**
     * An error a report throws under a binding of another identity escapes the
     * kit rather than passing as a refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnErrorFromAReportEscapes(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The adapter failed.');

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->factor,
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            $this->challengeAdmission(),
            static fn (): bool => throw new \RuntimeException('The adapter failed.'),
        );
    }

    /**
     * The kit rejects a replay check of a factor it can read no count for, as
     * one that counts no failure.
     *
     * @return void
     */
    public function testRejectsAReplayCheckOfAFactorWithNoStoredCount(): void
    {
        $unstored = (new Factor)->forceFill(['id' => '01JUNSTOREDFACTOR000000000']);

        self::rejects(fn () => ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($unstored, static fn (): \Closure => static function (): void {
            // A replay that changes nothing.
        }, static function (): void {
            // A path that counts nothing.
        }));
    }

    /**
     * The kit rejects a challenge path that counts a consumed challenge
     * answered again as a success.
     *
     * @return void
     */
    public function testRejectsAPathThatPassesAReplay(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($this->factor, function (): \Closure {
            $this->consumeChallenge();

            $caller = Callers::of($this->user, 'web');

            return function () use ($caller): void {
                DB::connection(StorageConnection::name())->transaction(fn () => $this->counters()->report($caller, $this->factor, $this->emailBinding($this->user), true));
            };
        }, $this->failChallenge(...)));
    }

    /**
     * The kit rejects a replay check whose failing path counts nothing, since a
     * reset could not then be seen.
     *
     * @return void
     */
    public function testRejectsAReplayCheckThatCountsNoFailure(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($this->factor, $this->consumeChallenge(...), static function (): void {
            // A path that checks its own code and never reports the outcome.
        }));
    }

    /**
     * The person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function countedIdentity(): MultiFactorAuthenticatable
    {
        return $this->user;
    }

    /**
     * The person's email factor.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    #[\Override]
    protected function countedFactor(): EloquentFactor&Model
    {
        return $this->factor;
    }

    /**
     * A pending factor of the person's, holding no enrolment.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    #[\Override]
    protected function pendingFactor(): EloquentFactor&Model
    {
        return Factor::query()->create([
            'authenticatable_type' => $this->user->getMorphClass(),
            'authenticatable_id'   => (string) $this->user->id,
            'type'                 => 'email',
            'destination'          => 'pending@example.test',
        ]);
    }

    /**
     * The person's sign-in binding.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function countedBinding(): ProofBinding
    {
        return $this->emailBinding($this->user);
    }

    /**
     * Send a code through the default gateway, once, and submit a wrong one to
     * its challenge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function failChallenge(): void
    {
        $gateway = $this->container()->make(ChallengeGateway::class);
        $binding = $this->emailBinding($this->user);

        $this->challenge ??= (string) $gateway->send(Callers::current(), $this->factor, $binding)->challengeId;

        $code = self::lastEmailedCode($this->mailbox);

        $gateway->verify(Callers::current(), $this->factor, $binding, $this->challenge, $code === '000000' ? '111111' : '000000');
    }

    /**
     * Send a code through the default gateway and answer it rightly; answering
     * it again submits the same code to the same challenge.
     *
     * @return \Closure(): void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function consumeChallenge(): \Closure
    {
        $gateway   = $this->container()->make(ChallengeGateway::class);
        $binding   = $this->emailBinding($this->user);
        $challenge = (string) $gateway->send(Callers::current(), $this->factor, $binding)->challengeId;
        $code      = self::lastEmailedCode($this->mailbox);

        self::assertTrue($gateway->verify(Callers::current(), $this->factor, $binding, $challenge, $code)->hasPassed());

        $factor = $this->factor;

        return static function () use ($gateway, $factor, $binding, $challenge, $code): void {
            $gateway->verify(Callers::current(), $factor, $binding, $challenge, $code);
        };
    }

    /**
     * Another person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function otherCountedIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'other-counted@example.test']);
    }

    /**
     * Ask the counters whether they admit the challenge, as an owner would.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    #[\Override]
    protected function isChallengeAdmitted(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): bool
    {
        if ($this->admitsAnything) {
            return true;
        }

        $call = fn (): bool => $this->counters()->isUsable(Callers::of($identity, $binding->application), $factor, $binding)->isAdmitted();

        return (bool) $this->asBroken('admit', $call);
    }

    /**
     * Report the challenge's outcome to the counters, as an owner would.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $passed
     * @return bool
     */
    #[\Override]
    protected function isChallengeReported(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): bool
    {
        $call = fn (): mixed => $this->counters()->report(Callers::of($identity, $binding->application), $factor, $binding, $passed);

        return $this->asBroken('report', $call) !== null;
    }

    /**
     * The counters.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function counters(): ChallengeCounters
    {
        return $this->container()->make(ChallengeCounters::class);
    }

    /**
     * The factor's failures in a row, as committed or as the open transaction
     * sees them.
     *
     * @return int
     */
    private function storedFailures(): int
    {
        $count = WriteConnection::query($this->factor->newQuery())->whereKey($this->factor->getKey())->value('consecutive_failures');

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Give the factor a live enrolment bound to the binding's sign-in, as an
     * enrolment challenge would admit.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function enroll(EloquentFactor&Model $factor, ProofBinding $binding): void
    {
        $this->container()->make(PendingEnrollments::class)->create(
            (string) LockedFactors::idOf($factor),
            hash('sha256', 'grant'),
            new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, Purpose::ENROLLMENT),
            0,
            EnrollmentAuthorization::STEP_UP,
            CarbonImmutable::now()->addHour(),
        );
    }

    /**
     * Run a check that must reject what it is given.
     *
     * @param  \Closure(): void  $check
     * @return void
     */
    private static function rejects(\Closure $check): void
    {
        try {
            $check();
        } catch (AssertionFailedError) {
            return;
        }

        self::fail('The kit was expected to reject the path.');
    }

    /**
     * Count a failure against the factor directly, as a path that checks no
     * admission would.
     *
     * @return void
     */
    private function countAFailure(): void
    {
        WriteConnection::query($this->factor->newQuery())->whereKey($this->factor->getKey())->increment($this->factor->getConsecutiveFailuresName());
    }

    /**
     * A report that counts a failure against the factor, whatever it is told,
     * and answers whether it counted one.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     */
    private function hasChargedTheFactor(EloquentFactor&Model $factor): bool
    {
        return WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->increment($factor->getConsecutiveFailuresName()) > 0;
    }

    /**
     * A report that counts a failure against the identity, whatever it is told.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    private function hasChargedTheIdentity(EloquentFactor&Model $factor, ProofBinding $binding): bool
    {
        $owner = ProofOwner::of($this->user);

        return IdentityState::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key)->increment('consecutive_failures') > 0;
    }

    /**
     * Make the hook's call as the test says: in a transaction of its own, with
     * a `LogicException` swallowed, or as it is.
     *
     * @param  string  $hook
     * @param  \Closure(): mixed  $call
     * @return mixed
     */
    private function asBroken(string $hook, \Closure $call): mixed
    {
        if ($this->ownTransaction === $hook) {
            return DB::connection(StorageConnection::name())->transaction($call);
        }

        if ($this->swallows !== $hook) {
            return $call();
        }

        try {
            return $call();
        } catch (\LogicException) {
            return null;
        }
    }
}
