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
 * The package's own challenge gateway passes, counting every outcome inside its
 * transaction.
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
     * A pending factor holding a live enrolment, given as one with none.
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
     * Even when the pending factor given is refused.
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
     * Its report changes the factor's count, though not the identity's.
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
     * The kit raises the counts first so the reset shows.
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
     * Its failed outcome alone is counted against the factor.
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
     * The kit raises the identity's count first so the reset shows.
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
     * Its failed outcome is counted and its passed outcome takes it back.
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
     * Counting in a transaction of its own, committed whatever becomes of the
     * change.
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
     * Its failure propagates.
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
     * @return void
     */
    public function testRejectsAPathThatChallengesADisabledFactor(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertADisabledFactorIsNotChallenged($this->factor, $this->countAFailure(...));
    }

    /**
     * Even though its report is sound.
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
     * Even though its admission is sound.
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
     * Inside one, sound calls would not be refused.
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
     * Not even the identity's own binding.
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
     * Answering `false` and counting nothing, as an adapter whose contract
     * refuses by value does.
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
     * @return iterable<string, array{string, string}>
     */
    public static function chargedCounts(): iterable
    {
        yield 'the factor\'s' => ['factor', 'A report under a binding of another identity must change no factor\'s count.'];
        yield 'the identity\'s' => ['identity', 'A report under a binding of another identity must change no identity\'s count.'];
        yield 'the other identity\'s' => ['other', 'A report under a binding of another identity must count nothing against it.'];
    }

    /**
     * A path that refuses such a report only once it has counted it.
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
     * So a hook that swallows the counters' refusal fails them.
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
     * So a hook that swallows the counters' refusal fails them.
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
     * So a path that admits anything fails the binding and enrolment checks.
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
     * The caller's transaction is left rolled back.
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
     * Ending the caller's nested transaction early to count in the outer one;
     * both roll back.
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
     * Its count would land in the outer transaction.
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
     * The kit puts the limits back afterwards.
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
     * Counting against the factor once the identity is locked.
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
     * So a host's factor limit at or below it does not lock the factor first;
     * the host's limit is put back after.
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
     * The counters would rightly admit its binding.
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
     * Rather than passing as a refusal.
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
     * As one that counts no failure.
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
     * A consumed challenge answered again is counted as a success.
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
     * A reset could not then be seen.
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
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function countedIdentity(): MultiFactorAuthenticatable
    {
        return $this->user;
    }

    /**
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    #[\Override]
    protected function countedFactor(): EloquentFactor&Model
    {
        return $this->factor;
    }

    /**
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
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function countedBinding(): ProofBinding
    {
        return $this->emailBinding($this->user);
    }

    /**
     * Sends a code once and submits a wrong one.
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
     * Answering again submits the same code to the same challenge.
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
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function otherCountedIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'other-counted@example.test']);
    }

    /**
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
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function counters(): ChallengeCounters
    {
        return $this->container()->make(ChallengeCounters::class);
    }

    /**
     * As committed, or as the open transaction sees them.
     *
     * @return int
     */
    private function storedFailures(): int
    {
        $count = WriteConnection::query($this->factor->newQuery())->whereKey($this->factor->getKey())->value('consecutive_failures');

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * A live enrolment bound to the binding's sign-in, as an enrolment
     * challenge would admit.
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
     * As a path that checks no admission would.
     *
     * @return void
     */
    private function countAFailure(): void
    {
        WriteConnection::query($this->factor->newQuery())->whereKey($this->factor->getKey())->increment($this->factor->getConsecutiveFailuresName());
    }

    /**
     * Counts a failure whatever it is told, and answers whether it counted one.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     */
    private function hasChargedTheFactor(EloquentFactor&Model $factor): bool
    {
        return WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->increment($factor->getConsecutiveFailuresName()) > 0;
    }

    /**
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
     * In a transaction of its own, with a `LogicException` swallowed, or as it
     * is.
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
