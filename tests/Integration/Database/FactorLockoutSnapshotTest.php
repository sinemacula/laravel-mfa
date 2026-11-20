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
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\Integration\Database\Concerns\RacesAForkedWorker;
use Tests\TestCase;

/**
 * A lockout or send `observer` commits after the application's transaction took
 * its snapshot still binds an attempt or send in it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptService::class)]
#[CoversClass(CodeService::class)]
final class FactorLockoutSnapshotTest extends TestCase
{
    use ArrangesVerification, RacesAForkedWorker;

    /**
     * Ends a transaction a failed test left open before migrations roll back.
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
     * A plain read, `lockout()` included, misses it; the attempt does not.
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
            self::assertSerializationFailure($failure, 'mfa_identity_states');
        }

        DB::connection()->rollBack();

        $this->openTransaction('REPEATABLE READ');

        $outcome = $this->attemptThatMustNotVerify($user, $this->takeSnapshot($factor));

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOlderMysqlSnapshotCannotHideADeadlineWrittenToTheFactorAlone(): void
    {
        $this->requireDriver('mysql');

        [$user, $factor] = $this->arrange();

        $this->openTransaction('REPEATABLE READ');

        $stale = $this->takeSnapshot($factor);
        $until = $this->commitDeadlineToTheFactorAlone($factor);

        self::assertNull(Factor::query()->whereKey($factor->id)->value('locked_until'));

        $outcome = $this->attemptThatMustNotVerify($user, $stale);

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until, 0);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testPostgresqlReadCommittedFindsADeadlineWrittenToTheFactorAlone(): void
    {
        $this->requireDriver('pgsql');

        [$user, $factor] = $this->arrange();

        $this->openTransaction('READ COMMITTED');

        $stale = $this->takeSnapshot($factor);
        $until = $this->commitDeadlineToTheFactorAlone($factor);

        $outcome = $this->attemptThatMustNotVerify($user, $stale);

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until, 0);
    }

    /**
     * With the identity's lock uncontended, the factor's row lock raises it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPostgresqlRepeatableReadFailsOnTheFactorsRowWhenOnlyItChanged(): void
    {
        $this->requireDriver('pgsql');

        [$user, $factor] = $this->arrange();

        $this->openTransaction('REPEATABLE READ');

        $stale = $this->takeSnapshot($factor);
        $until = $this->commitDeadlineToTheFactorAlone($factor);

        self::assertNull(Factor::query()->whereKey($factor->id)->value('locked_until'));

        try {
            $this->attemptThatMustNotVerify($user, $stale);

            self::fail('The stale snapshot must not answer the attempt.');
        } catch (\PDOException $failure) {
            self::assertSerializationFailure($failure, 'mfa_factors');
        }

        DB::connection()->rollBack();

        $this->openTransaction('REPEATABLE READ');

        $outcome = $this->attemptThatMustNotVerify($user, $this->takeSnapshot($factor));

        DB::connection()->commit();

        $this->assertRefusedByTheFactor($outcome, $user, $factor, $until, 0);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testPostgresqlRepeatableReadFailsASendPastTheCapUntilRetried(): void
    {
        $this->requireDriver('pgsql');

        [$user, $factor] = $this->arrangeSends();

        $this->openTransaction('REPEATABLE READ');
        $this->takeSnapshot($factor);
        $this->commitSendElsewhere($factor);
        $this->signInAgainElsewhere($user);

        try {
            $this->mfa()->sendCode(Callers::current(), $factor->id);

            self::fail('The stale snapshot must not answer the send.');
        } catch (\PDOException $failure) {
            self::assertSerializationFailure($failure, 'mfa_identity_states');
        }

        DB::connection()->rollBack();

        $this->openTransaction('REPEATABLE READ');

        $result = $this->mfa()->sendCode(Callers::current(), $factor->id);

        DB::connection()->commit();

        self::assertSame(FailureReason::SENDING_CAPPED, $result->reason);
        $this->assertSentOnce();
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testPostgresqlReadCommittedCapsASendAnotherJustCommitted(): void
    {
        $this->requireDriver('pgsql');

        [$user, $factor] = $this->arrangeSends();

        $this->openTransaction('READ COMMITTED');
        $this->takeSnapshot($factor);
        $this->commitSendElsewhere($factor);
        $this->signInAgainElsewhere($user);

        $result = $this->mfa()->sendCode(Callers::current(), $factor->id);

        DB::connection()->commit();

        self::assertSame(FailureReason::SENDING_CAPPED, $result->reason);
        $this->assertSentOnce();
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testASendWaitingOnAnotherIsCappedOnceItCommits(): void
    {
        if (!in_array(DB::connection()->getDriverName(), ['mysql', 'pgsql'], true)) {
            self::markTestSkipped('Overlapping sends are proven on MySQL and PostgreSQL.');
        }

        $this->needsAFork();

        [$user, $factor] = $this->arrangeSends();

        $outcome = $this->holdingTheLock(
            fn () => self::assertTrue($this->mfa()->sendCode(Callers::current(), $factor->id)->wasSent()),
            function () use ($user, $factor): ?FailureReason {
                $this->signInAgainElsewhere($user);

                $reason = $this->mfa()->sendCode(Callers::current(), $factor->id)->reason;

                // Only the worker's copy of the mailbox shows its delivery.
                self::assertCount(1, $this->mailbox->sent());

                return $reason;
            },
        );

        self::assertSame(FailureReason::SENDING_CAPPED->value, $outcome);
        $this->assertSentOnce();
    }

    /**
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
        $config->set('database.connections.racer', $config->get('database.connections.testing'));
    }

    /**
     * @param  \PDOException  $failure
     * @param  string  $table
     * @return void
     */
    private static function assertSerializationFailure(\PDOException $failure, string $table): void
    {
        $query = $failure instanceof QueryException ? $failure : $failure->getPrevious();

        self::assertInstanceOf(QueryException::class, $query);
        self::assertSame('40001', (string) $query->getCode());
        self::assertStringContainsString($table, $query->getSql());
    }

    /**
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
     * One failure reaches the factor's limit but not the identity's.
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
     * An email factor whose destination takes one send, for a signed-in person
     * whose state row exists.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function arrangeSends(): array
    {
        $this->arrangeVerification();

        config()->set('mfa.codes.factor_send_limit', 1);

        $this->requestFrom('203.0.113.1');

        $user  = $this->signedInPerson();
        $owner = ProofOwner::of($user);

        IdentityState::query()->create(['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key]);

        return [$user, $this->emailFactor($user)];
    }

    /**
     * MySQL sets the level before the transaction, PostgreSQL inside it.
     *
     * @param  'READ COMMITTED'|'REPEATABLE READ'  $isolation
     * @return void
     */
    private function openTransaction(string $isolation): void
    {
        $connection = DB::connection();
        $statement  = 'SET TRANSACTION ISOLATION LEVEL ' . $isolation;

        if ($connection->getDriverName() === 'mysql') {
            $connection->unprepared($statement);
            $connection->beginTransaction();

            return;
        }

        $connection->beginTransaction();
        $connection->unprepared($statement);
    }

    /**
     * A plain read fixes a repeatable-read snapshot, as an application's would.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function takeSnapshot(Factor $factor): Factor
    {
        return Factor::query()->findOrFail($factor->id);
    }

    /**
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
     * From the first sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function commitSendElsewhere(Factor $factor): void
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            self::assertTrue($this->mfa()->sendCode(Callers::current(), $factor->id)->wasSent());
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * From another address, so the two sends share no throttle row and meet
     * only at the identity's lock.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function signInAgainElsewhere(TestUser $user): void
    {
        $this->requestFrom('203.0.113.2');
        $this->beginSignIn($user, 'sign-in-b');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \Carbon\CarbonImmutable
     */
    private function commitDeadlineToTheFactorAlone(Factor $factor): CarbonImmutable
    {
        $until = CarbonImmutable::now()->addHour();

        DB::connection('observer')->table('mfa_factors')->where('id', $factor->id)->update(['locked_until' => $until]);

        return $until;
    }

    /**
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
     * Only the observer's failures count, and the identity stays unlocked.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome  $outcome
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  \Carbon\CarbonImmutable  $until
     * @param  int  $failures
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function assertRefusedByTheFactor(AttemptOutcome $outcome, TestUser $user, Factor $factor, CarbonImmutable $until, int $failures = 1): void
    {
        self::assertTrue($outcome->isRefused());
        self::assertSame(AttemptScope::FACTOR, $outcome->lockout?->scope);
        self::assertSame($until->getTimestamp(), $outcome->lockout->until?->getTimestamp());

        $stored = Factor::query()->findOrFail($factor->id);

        self::assertSame($failures, $stored->getConsecutiveFailures());
        self::assertSame($until->getTimestamp(), $stored->getLockedUntil()?->getTimestamp());

        $state = IdentityState::query()->where('authenticatable_id', (string) $user->id)->sole();

        self::assertSame($failures, $state->consecutive_failures);
        self::assertNull($state->locked_until);

        $key = $this->container()->make(AttemptKeys::class)->identity($user::class, (string) $user->id);

        self::assertSame($failures, $this->container()->make(AttemptStore::class)->read([$key])[$key]['hits'] ?? 0);
    }

    /**
     * @return void
     */
    private function assertSentOnce(): void
    {
        self::assertSame(1, Code::query()->count());
        self::assertCount(1, $this->mailbox->sent());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): AttemptService
    {
        return $this->container()->make(AttemptService::class);
    }
}
