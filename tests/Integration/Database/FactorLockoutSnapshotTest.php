<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * A factor's lockout committed after an application's own transaction took its
 * snapshot still refuses an attempt made inside that transaction, as the
 * deadline is read off the factor's row under the factor state lock.
 *
 * The package's tables live on the default connection, which the application's
 * transaction is opened on; a second connection to the same database,
 * `observer`, stands in for a concurrent request and commits the lockout with a
 * real failed attempt. A plain read inside the transaction shows the snapshot
 * is older than that commit. The identity is kept below its own limit, so only
 * the factor's lockout can refuse the attempt.
 *
 * The databases differ, and each is held to what it documents: MySQL answers a
 * locking read inside `REPEATABLE READ` with the row as committed, so the
 * attempt is refused where it stands. PostgreSQL's `READ COMMITTED` takes a new
 * snapshot for every statement, so it refuses too; under its `REPEATABLE READ`
 * locking a row changed since the snapshot is a serialisation failure, and the
 * whole outer transaction is to be retried, when the attempt is refused.
 *
 * SQLite serialises every writer on the whole file, so these tests run on the
 * server databases only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptService::class)]
final class FactorLockoutSnapshotTest extends TestCase
{
    /**
     * End a transaction a failed test left open, before the migrations roll
     * back on the same connection.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * On MySQL, a lockout committed after the snapshot is hidden from a plain
     * read, the advisory `lockout()` included, and still refuses the attempt
     * without running its verification.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOlderMysqlSnapshotCannotHideTheLockoutFromAnAttempt(): void
    {
        $this->requireDriver('mysql');

        [$user, $factor] = $this->arrange();

        $this->openTransaction('REPEATABLE READ');

        $stale = $this->takeSnapshot($factor);
        $until = $this->commitLockoutElsewhere($user, $factor);

        self::assertNull($stale->getLockedUntil());
        self::assertNull(Factor::query()->whereKey($factor->id)->value('locked_until'));
        self::assertNull($this->service()->lockout($user, $stale));

        $outcome = $this->attemptThatMustNotVerify($user, $stale);

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until);
    }

    /**
     * On PostgreSQL's `READ COMMITTED`, every statement sees what has been
     * committed, so the read and the attempt alike find the lockout.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPostgresqlReadCommittedFindsTheLockout(): void
    {
        $this->requireDriver('pgsql');

        [$user, $factor] = $this->arrange();

        $this->openTransaction('READ COMMITTED');

        $stale = $this->takeSnapshot($factor);
        $until = $this->commitLockoutElsewhere($user, $factor);

        self::assertSame(AttemptScope::FACTOR, $this->service()->lockout($user, $stale)?->scope);

        $outcome = $this->attemptThatMustNotVerify($user, $stale);

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until);
    }

    /**
     * On PostgreSQL's `REPEATABLE READ`, taking the lock on a row changed since
     * the snapshot fails with a serialisation failure rather than answer from
     * it; retrying the whole outer transaction then refuses the attempt, and
     * the verification runs in neither.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPostgresqlRepeatableReadFailsUntilTheOuterTransactionIsRetried(): void
    {
        $this->requireDriver('pgsql');

        [$user, $factor] = $this->arrange();

        $this->openTransaction('REPEATABLE READ');

        $stale = $this->takeSnapshot($factor);
        $until = $this->commitLockoutElsewhere($user, $factor);

        self::assertNull(Factor::query()->whereKey($factor->id)->value('locked_until'));

        try {
            $this->attemptThatMustNotVerify($user, $stale);

            self::fail('The stale snapshot must not answer the attempt.');
        } catch (\PDOException $failure) {
            self::assertSerializationFailure($failure);
        }

        DB::connection()->rollBack();

        $this->openTransaction('REPEATABLE READ');

        $outcome = $this->attemptThatMustNotVerify($user, $this->takeSnapshot($factor));

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until);
    }

    /**
     * Add the observer: a second connection to the test database.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.observer', $config->get('database.connections.testing'));
    }

    /**
     * Assert the failure is the database's serialisation failure, however the
     * nested transaction raised it.
     *
     * @param  \PDOException  $failure
     * @return void
     */
    private static function assertSerializationFailure(\PDOException $failure): void
    {
        $query = $failure instanceof QueryException ? $failure : $failure->getPrevious();

        self::assertInstanceOf(QueryException::class, $query);
        self::assertSame('40001', (string) $query->getCode());
    }

    /**
     * Skip unless the test database is the given one.
     *
     * @param  string  $driver
     * @return void
     */
    private function requireDriver(string $driver): void
    {
        if (DB::connection()->getDriverName() === $driver) {
            return;
        }

        self::markTestSkipped(sprintf('This behaviour belongs to %s.', $driver));
    }

    /**
     * Commit a user, a confirmed factor and the identity's state row, with a
     * limit that one failure of the factor reaches and the identity's does not.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function arrange(): array
    {
        config()->set('mfa.attempts.factor_limit', 1);
        config()->set('mfa.attempts.identity_limit', 20);

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'snapshot@example.com']);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        IdentityState::query()->create(['authenticatable_type' => $user::class, 'authenticatable_id' => (string) $user->id]);

        return [$user, $factor];
    }

    /**
     * Open the application's own transaction at the isolation level, which
     * MySQL takes for its next transaction and PostgreSQL inside the current
     * one.
     *
     * @param  string  $isolation
     * @return void
     */
    private function openTransaction(string $isolation): void
    {
        $connection = DB::connection();
        $statement  = sprintf('SET TRANSACTION ISOLATION LEVEL %s', $isolation);

        if ($connection->getDriverName() === 'mysql') {
            $connection->unprepared($statement);
            $connection->beginTransaction();

            return;
        }

        $connection->beginTransaction();
        $connection->unprepared($statement);
    }

    /**
     * Read the factor with a plain read, as an application's transaction does
     * before it verifies, which fixes the snapshot of a repeatable read. It is
     * the copy the attempt is then made with.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function takeSnapshot(Factor $factor): Factor
    {
        return Factor::query()->findOrFail($factor->id);
    }

    /**
     * Lock the factor from the observer with a real failed attempt, as a
     * concurrent request would, and return the deadline as committed.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \Carbon\CarbonImmutable
     *
     * @throws \Throwable
     */
    private function commitLockoutElsewhere(TestUser $user, Factor $factor): CarbonImmutable
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            $failed = $this->service()->attempt(
                new Attempt($user, Factor::query()->findOrFail($factor->id), Purpose::SIGN_IN),
                static fn (): bool => false,
            );

            self::assertTrue($failed->isFailed());

            $until = Factor::query()->findOrFail($factor->id)->getLockedUntil();
        } finally {
            config()->set('mfa.storage.connection', null);
        }

        self::assertNotNull($until);

        return CarbonImmutable::instance($until);
    }

    /**
     * Make an attempt on the application's connection whose verification must
     * never run.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \Throwable
     */
    private function attemptThatMustNotVerify(TestUser $user, Factor $factor): AttemptOutcome
    {
        return $this->service()->attempt(new Attempt($user, $factor, Purpose::SIGN_IN), static function (): bool {
            throw new MidRotationFailureException('A locked factor must not reach its driver.');
        });
    }

    /**
     * Assert the factor's own lockout refused the attempt, and that nothing but
     * the one failure the observer made is counted, with the deadline as it
     * committed and the identity below its limit, unlocked.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome  $outcome
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  \Carbon\CarbonImmutable  $until
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function assertRefusedByTheFactor(AttemptOutcome $outcome, TestUser $user, Factor $factor, CarbonImmutable $until): void
    {
        self::assertTrue($outcome->isRefused());
        self::assertSame(AttemptScope::FACTOR, $outcome->lockout?->scope);
        self::assertSame($until->getTimestamp(), $outcome->lockout->until?->getTimestamp());

        $stored = Factor::query()->findOrFail($factor->id);

        self::assertSame(1, $stored->getConsecutiveFailures());
        self::assertSame($until->getTimestamp(), $stored->getLockedUntil()?->getTimestamp());

        $state = IdentityState::query()->where('authenticatable_id', (string) $user->id)->sole();

        self::assertSame(1, $state->consecutive_failures);
        self::assertNull($state->locked_until);

        $key = $this->container()->make(AttemptKeys::class)->identity($user::class, (string) $user->id);

        self::assertSame(1, $this->container()->make(AttemptStore::class)->read([$key])[$key]['hits'] ?? null);
    }

    /**
     * Resolve the attempt service.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): AttemptService
    {
        return $this->container()->make(AttemptService::class);
    }
}
