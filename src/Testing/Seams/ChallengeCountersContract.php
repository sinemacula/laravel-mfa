<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * What a challenge owner's wiring to `Attempts\ChallengeCounters` must
 * guarantee: failures count inside the owner's transaction, so a rollback
 * counts nothing; the identity's limit locks it; a disabled factor or consumed
 * challenge never passes; and an enrolment challenge counts nothing.
 *
 * `$failChallenge` fails one challenge through the owner's own path. The
 * admission and report checks take the path's own calls, so they prove the
 * adapter's wiring rather than the package's counters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ChallengeCountersContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuses a confirmed factor and a pending one with no live enrolment, and
     * no outcome changes a count. Counts start above zero so a reset shows.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $confirmed
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $pending
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding): bool  $admit
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding, bool): bool  $report
     * @return void
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    public static function assertAnEnrollmentChallengeIsItsOwn(
        EloquentFactor&Model $confirmed,
        EloquentFactor&Model $pending,
        ProofBinding $binding,
        \Closure $admit,
        \Closure $report,
    ): void {
        $enrolling = new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, Purpose::ENROLLMENT);

        self::raiseFailures($confirmed, $binding);

        $before         = self::failures($confirmed);
        $identityBefore = self::identityFailures($binding);

        $connection = DB::connection(StorageConnection::name());

        $connection->transaction(static function () use ($confirmed, $pending, $binding, $enrolling, $admit, $report, $before, $identityBefore): void {

            Assert::assertFalse($admit($confirmed, $enrolling), 'A confirmed factor must not be challenged for enrolling.');
            Assert::assertFalse($admit($pending, $enrolling), 'A pending factor with no live enrolment must not be challenged.');

            foreach ([[false, 'failed'], [true, 'passed']] as [$passed, $outcome]) {
                $report($confirmed, $enrolling, $passed);

                Assert::assertSame($before, self::failures($confirmed), sprintf('An enrolment challenge\'s %s outcome must change no factor\'s count.', $outcome));
                Assert::assertSame($identityBefore, self::identityFailures($binding), sprintf('An enrolment challenge\'s %s outcome must change no identity\'s count.', $outcome));
            }
        });

        Assert::assertSame($before, self::failures($confirmed), 'An enrolment challenge\'s outcome must change no factor\'s count.');
        Assert::assertSame($identityBefore, self::identityFailures($binding), 'An enrolment challenge\'s outcome must change no identity\'s count.');
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    public static function assertAFailedChallengeIsCounted(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $before = self::failures($factor);

        self::attempt($failChallenge);

        Assert::assertSame($before + 1, self::failures($factor), 'A failed challenge must be counted against its factor.');
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertARolledBackChallengeCountsNothing(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $before     = self::failures($factor);
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        try {
            self::attempt($failChallenge);
        } finally {
            $connection->rollBack();
        }

        Assert::assertSame($before, self::failures($factor), 'A challenge whose change rolls back must count nothing.');
    }

    /**
     * Catches an owner that reports after commit, and one that leaves the
     * transaction other than it found it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertAFailureIsCountedBeforeTheCallerCommits(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $before     = self::failures($factor);
        $connection = DB::connection(StorageConnection::name());
        $level      = $connection->transactionLevel() + 1;

        $connection->beginTransaction();

        try {
            self::attempt($failChallenge);

            Assert::assertSame($level, $connection->transactionLevel(), 'A challenge must leave the caller\'s transaction as it found it.');
            Assert::assertSame($before + 1, self::failures($factor), 'A failed challenge must be counted in the caller\'s transaction, before it commits.');
        } finally {
            $connection->rollBack($level - 1);
        }
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertANestedRollbackCountsNothing(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $before     = self::failures($factor);
        $connection = DB::connection(StorageConnection::name());
        $outer      = $connection->transactionLevel() + 1;

        $connection->beginTransaction();

        try {
            $connection->beginTransaction();

            try {
                self::attempt($failChallenge);

                $left = $connection->transactionLevel();
            } finally {
                $connection->rollBack($outer);
            }

            Assert::assertSame($outer + 1, $left, 'A challenge must leave the caller\'s nested transaction as it found it.');

            $connection->commit();
        } finally {
            $connection->rollBack($outer - 1);
        }

        Assert::assertSame($before, self::failures($factor), 'A challenge whose nested transaction rolls back must count nothing.');
    }

    /**
     * Sets the identity's limit to two and the factor's above it, then restores
     * them; a failure past the lock counts nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(): void  $failChallenge
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertTheIdentityLimitLocksTheIdentity(
        MultiFactorAuthenticatable $identity,
        EloquentFactor&Model $factor,
        ProofBinding $binding,
        \Closure $failChallenge,
    ): void {
        $config = Container::getInstance()->make(Repository::class);
        $saved  = $config->get('mfa.attempts');

        $config->set(['mfa.attempts.factor_limit' => 20, 'mfa.attempts.identity_limit' => 2]);

        try {
            self::attempt($failChallenge);

            Assert::assertTrue(self::admission($identity, $factor, $binding)->isAdmitted(), 'A failure short of the identity\'s limit must not lock it.');

            self::attempt($failChallenge);

            Assert::assertSame(FailureReason::LOCKED, self::admission($identity, $factor, $binding)->reason, 'The failure reaching the identity\'s limit must lock it.');

            $before = self::failures($factor);

            self::attempt($failChallenge);

            Assert::assertSame($before, self::failures($factor), 'A challenge of a locked identity must count nothing more.');
        } finally {
            $config->set('mfa.attempts', $saved);
        }
    }

    /**
     * Answering it again resets no failures counted since.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): (\Closure(): void)  $consumeChallenge
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    public static function assertAConsumedChallengeIsNeverASuccessAgain(EloquentFactor&Model $factor, \Closure $consumeChallenge, \Closure $failChallenge): void
    {
        $replay = $consumeChallenge();

        self::attempt($failChallenge);

        $before = self::failures($factor);

        Assert::assertGreaterThan(0, $before, 'A failed challenge must be counted against its factor.');

        self::attempt($replay);

        Assert::assertGreaterThanOrEqual($before, self::failures($factor), 'A consumed challenge answered again must never be counted as a success.');
    }

    /**
     * A failed attempt on it counts nothing more.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    public static function assertADisabledFactorIsNotChallenged(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $factor->newQuery()->whereKey($factor->getKey())->update([$factor->getDisabledAtName() => CarbonImmutable::now()]);

        $before = self::failures($factor);

        self::attempt($failChallenge);

        Assert::assertSame($before, self::failures($factor), 'A disabled factor must not be challenged.');
    }

    /**
     * Admit and report each refuse outside a storage transaction. Call this
     * outside any transaction on that connection.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding): bool  $admit
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding, bool): bool  $report
     * @return void
     *
     * @formatter:on
     */
    public static function assertTheCountersNeedTheCallersTransaction(EloquentFactor&Model $factor, ProofBinding $binding, \Closure $admit, \Closure $report): void
    {
        Assert::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel(), 'The check must be made outside any transaction on the storage connection.');

        $admission = self::outcomeOf(static fn () => $admit($factor, $binding));
        $reporting = self::outcomeOf(static fn () => $report($factor, $binding, false));

        Assert::assertInstanceOf(\LogicException::class, $admission, 'The path must refuse to admit a challenge outside the caller\'s transaction.');
        Assert::assertInstanceOf(\LogicException::class, $reporting, 'The path must refuse to report a challenge outside the caller\'s transaction.');
    }

    /**
     * A refused report answers `false` or throws `OperationRefusedException`
     * and changes no count; any other exception escapes.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $other
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding): bool  $admit
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding, bool): bool  $report
     * @return void
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    public static function assertABindingOfAnotherIdentityIsRefused(
        EloquentFactor&Model $factor,
        ProofBinding $binding,
        MultiFactorAuthenticatable $other,
        \Closure $admit,
        \Closure $report,
    ): void {
        $owner   = ProofOwner::of($other);
        $foreign = new ProofBinding($owner->type, $owner->key, $binding->application, $binding->sessionId, Purpose::SIGN_IN);

        Assert::assertFalse($owner->type === $binding->identityType && $owner->key === $binding->identityKey, 'The other identity must not be the counted one.');

        $before         = self::failures($factor);
        $identityBefore = self::identityFailures($binding);

        DB::connection(StorageConnection::name())->transaction(static function () use ($factor, $binding, $foreign, $admit, $report): void {

            Assert::assertTrue($admit($factor, $binding), 'A challenge of the identity\'s own factor under its own binding must be admitted.');
            Assert::assertFalse($admit($factor, $foreign), 'A binding of another identity must not be admitted.');
            Assert::assertTrue(self::refuses(static fn (): bool => $report($factor, $foreign, false)), 'A report under a binding of another identity must be refused.');
        });

        Assert::assertSame($before, self::failures($factor), 'A report under a binding of another identity must change no factor\'s count.');
        Assert::assertSame($identityBefore, self::identityFailures($binding), 'A report under a binding of another identity must change no identity\'s count.');
        Assert::assertSame(0, self::identityFailures($foreign), 'A report under a binding of another identity must count nothing against it.');
    }

    /**
     * A refusal the path throws is the owner's way of saying no.
     *
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    private static function attempt(\Closure $failChallenge): void
    {
        try {
            $failChallenge();
        } catch (\RuntimeException) {
            // A refused challenge counts nothing; the count is read after.
        }
    }

    /**
     * Asked in a transaction of the kit's own.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Throwable
     */
    private static function admission(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): ChallengeAdmission
    {
        $caller = CallerContext::forIdentity($identity, $binding->application);

        return DB::connection(StorageConnection::name())->transaction(static fn (): ChallengeAdmission => self::counters()->isUsable($caller, $factor, $binding));
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return int
     */
    private static function failures(EloquentFactor&Model $factor): int
    {
        $count = WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->value($factor->getConsecutiveFailuresName());

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return int
     */
    private static function identityFailures(ProofBinding $binding): int
    {
        $count = WriteConnection::query(IdentityState::query())
            ->where('authenticatable_type', $binding->identityType)
            ->where('authenticatable_id', $binding->identityKey)
            ->value('consecutive_failures');

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * `false` or `OperationRefusedException`; any other exception escapes.
     *
     * @param  \Closure(): bool  $report
     * @return bool
     */
    private static function refuses(\Closure $report): bool
    {
        try {
            return !$report();
        } catch (OperationRefusedException) {
            return true;
        }
    }

    /**
     * `null` when the call threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return ?\Throwable
     */
    private static function outcomeOf(\Closure $call): ?\Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     */
    private static function raiseFailures(EloquentFactor&Model $factor, ProofBinding $binding): void
    {
        WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->increment($factor->getConsecutiveFailuresName());

        IdentityState::query()
            ->firstOrCreate(['authenticatable_type' => $binding->identityType, 'authenticatable_id' => $binding->identityKey])
            ->increment('consecutive_failures');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     */
    private static function counters(): ChallengeCounters
    {
        return Container::getInstance()->make(ChallengeCounters::class);
    }
}
