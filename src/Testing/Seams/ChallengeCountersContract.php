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
 * guarantee, as assertions: a failed challenge is counted against the factor,
 * inside the owner's transaction and before it commits, so one that rolls back
 * counts nothing, a nested one included, and the caller's transaction is left
 * as it was found; the identity's limit locks it, after which a failure counts
 * nothing more; a factor disabled at the failure ceiling is not challenged; a
 * consumed challenge answered again is never a success; the path's own calls
 * refuse a call outside a transaction and a binding of another identity; and a
 * challenge for enrolling admits no confirmed factor and counts nothing.
 *
 * The closure given fails one challenge of the identity's factor through the
 * owner's own path, as a person submitting a wrong code would. The admission
 * and report checks are handed the path's own calls, so what they prove is the
 * adapter's wiring, not the package's counters: an adapter that opens its own
 * transaction around them, swallows their refusal or admits what they refuse is
 * caught.
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
     * Under a binding whose purpose is `enrollment`, a confirmed factor is
     * refused and a pending one with no live enrolment too; and an outcome
     * reported for one, failed or passed, changes no failure count of the
     * factor or the identity, read after each outcome and again once the
     * transaction commits. Both counts are raised above zero first, so a passed
     * outcome that wrongly resets them shows.
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
     * A failed challenge adds one to the factor's failures in a row.
     *
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
     * A failed challenge inside a change on the storage connection that rolls
     * back counts nothing.
     *
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
     * A failed challenge is counted inside the transaction it is made in,
     * before that commits, so an owner that reports later, once it has
     * committed, is caught; and the owner leaves that transaction as it found
     * it.
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
     * A failed challenge inside a nested transaction that rolls back, within an
     * outer one that commits, counts nothing.
     *
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
     * The identity's limit locks it: a failure short of the limit leaves the
     * factor admitted, the failure that reaches it refuses the factor as
     * locked, and a further failure counts nothing. The limits are set for the
     * check, the identity's to two and the factor's above it, and put back
     * after it.
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
     * A challenge answered rightly is consumed: answering it again is never
     * counted as a success, so it resets no failures counted since.
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
     * A factor disabled at the failure ceiling is not challenged, so a failed
     * attempt on it counts nothing more.
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
     * The path refuses to admit or to report outside a transaction on the
     * storage connection, each on its own: it neither opens one of its own nor
     * swallows the counters' refusal. The check must itself be made outside any
     * transaction on that connection.
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
     * The path admits a challenge of the identity's own factor under its own
     * binding, and refuses one under the same binding naming another identity:
     * it admits nothing, and a report under it is refused, by answering `false`
     * or throwing an `OperationRefusedException`, and changes no count of the
     * factor or of either identity. Any other exception is an error, not a
     * refusal, and escapes.
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
     * Fail one challenge through the owner's path; a refusal it throws is the
     * owner's way of saying no.
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
     * Whether the counters admit a challenge of the factor now, asked in a
     * transaction of the kit's own.
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
     * The factor's failures in a row, as stored.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return int
     */
    private static function failures(EloquentFactor&Model $factor): int
    {
        $count = WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->value($factor->getConsecutiveFailuresName());

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * The failures in a row, as stored, of the identity the binding names.
     *
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
     * Whether a report was refused: it answered `false`, or threw an
     * `OperationRefusedException`. Any other exception escapes.
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
     * What a call threw, or `null` when it threw nothing.
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
     * Raise the factor's failures in a row and the identity's by one each, as
     * stored.
     *
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
     * The counters, as the container builds them.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     */
    private static function counters(): ChallengeCounters
    {
        return Container::getInstance()->make(ChallengeCounters::class);
    }
}
