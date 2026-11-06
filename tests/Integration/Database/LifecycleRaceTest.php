<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Lifecycle\IdentityReset;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\RecordingSessionRevoker;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\TestCase;

/**
 * Removals and resets overlapping with one another, on MySQL and PostgreSQL.
 *
 * The package's tables live on the default connection, which a second
 * connection to the same database, `observer`, stands in for a concurrent
 * request on, with a lock timeout of a second. While one change holds the
 * identity's factor state lock, a parallel one cannot read what it would decide
 * on: it waits for the lock and times out, and once the first has committed it
 * finds what the first left.
 *
 * - Of two removals on the last two factors of an identity a factor is required
 *   of, the second waits and is then refused as the last factor: both cannot
 *   pass. One test runs the second on the observer until it times out; another
 *   runs it in a forked worker on a connection of its own, and commits the
 *   first only once the database reports the worker waiting on the lock.
 * - A verification that overlaps a reset waits, then fails, its factor gone.
 *   One test runs it on the observer until it times out and retries; another
 *   runs it in a forked worker and lets that same verification resume when the
 *   reset commits.
 * - A verification that committed first keeps its success, which nothing can
 *   undo, but the reset invalidates its proof.
 *
 * SQLite serialises every writer on the whole file, so these tests run on the
 * server databases only; the feature tests prove the same checks on one
 * connection, with the other change interleaved before the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleService::class)]
#[CoversClass(IdentityReset::class)]
final class LifecycleRaceTest extends TestCase
{
    use ArrangesPasskeys;

    /** @var int How long to wait for the worker, in microseconds, between looks. */
    private const int POLL_INTERVAL = 150000;

    /** @var int How many times to look for the worker waiting on the lock. */
    private const int POLLS = 400;

    /**
     * Skip on SQLite, and give the observer a lock timeout of a second.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $driver = DB::connection()->getDriverName();

        if (!in_array($driver, ['mysql', 'pgsql'], true)) {
            self::markTestSkipped('Overlapping removals and resets are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * Of two removals on the last two factors, the second waits for the first
     * to commit, then is refused: exactly one passes, and one factor is left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoConcurrentRemovalsCannotBothPassOnTheLastTwoFactors(): void
    {
        $this->enablePasskeys(['requirement' => 'always']);

        $user   = $this->signedInPerson();
        $first  = $this->confirmedFactor($user);
        $second = $this->confirmedFactor($user);

        $this->stepUpWith($user, $first);
        $this->stepUpWith($user, $second);

        $stopped = null;

        Factor::deleting(function () use ($first, &$stopped): void {

            if ($stopped !== null) {
                return;
            }

            $stopped = false;

            try {
                $this->asObserver(static fn (): FactorRemovalResult => Mfa::removeFactor(Callers::current(), $first->id));
            } catch (QueryException $exception) {
                $stopped = $exception;
            }
        });

        try {
            $passed = Mfa::removeFactor(Callers::current(), $second->id);
        } finally {
            Factor::flushEventListeners();
        }

        self::assertTrue($passed->wasMade());
        self::assertInstanceOf(QueryException::class, $stopped);

        self::assertSame(FailureReason::LAST_FACTOR, Mfa::removeFactor(Callers::current(), $first->id)->reason);
        self::assertSame([$first->id], Factor::query()->pluck('id')->all());
    }

    /**
     * Of two removals truly overlapping, the first holding the lock uncommitted
     * while a worker's removal waits on it, the worker is refused once the
     * first commits. A revoker that advances nothing stands in for an
     * authentication layer's, so the worker's copy of the session's proofs
     * keeps counting and only the last factor check can refuse it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoOverlappingRemovalsTheSecondWaitsAndIsRefused(): void
    {
        $this->needsAFork();
        $this->enablePasskeys(['requirement' => 'always']);
        $this->container()->instance(SessionRevoker::class, new RecordingSessionRevoker);

        $user   = $this->signedInPerson();
        $first  = $this->confirmedFactor($user);
        $second = $this->confirmedFactor($user);

        // Of a type no application enables, so it never counts as covering the
        // identity, but its proof is made without either of the other two.
        $this->stepUpWith($user, $this->confirmedFactor($user, 'sms'));

        $outcome = $this->holdingTheLock(
            static fn () => self::assertTrue(Mfa::removeFactor(Callers::current(), $second->id)->wasMade()),
            static fn (): ?FailureReason => Mfa::removeFactor(Callers::current(), $first->id)->reason,
        );

        self::assertSame(FailureReason::LAST_FACTOR->value, $outcome);
        self::assertFalse(Factor::query()->whereKey($second->id)->exists());
        self::assertTrue(Factor::query()->whereKey($first->id)->exists());
    }

    /**
     * A verification that read the factor before a reset commits waits on the
     * lock the reset holds, and when it commits the same verification resumes
     * and fails: the factor it read is gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationWaitingOnAResetFailsWhenItResumes(): void
    {
        $this->needsAFork();
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $factor->update(AuthenticatorApp::FACTOR);

        $code = AuthenticatorApp::code($factor);

        $outcome = $this->holdingTheLock(
            static fn () => Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.'),
            static fn (): ?FailureReason => Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->reason,
        );

        self::assertSame(FailureReason::NOT_FOUND->value, $outcome);
        self::assertFalse(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * A verification overlapping a reset waits for it to commit, then fails:
     * the factor it read is gone, and no proof is recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationOverlappingAResetFails(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $factor->update(AuthenticatorApp::FACTOR);

        $code    = AuthenticatorApp::code($factor);
        $stopped = null;

        Factor::deleting(function () use ($factor, $code, &$stopped): void {

            if ($stopped !== null) {
                return;
            }

            $stopped = false;

            try {
                $this->asObserver(static fn (): VerificationResult => Mfa::verify(Callers::current(), Submission::factor($factor->id, $code)));
            } catch (QueryException $exception) {
                $stopped = $exception;
            }
        });

        try {
            Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.');
        } finally {
            Factor::flushEventListeners();
        }

        self::assertInstanceOf(QueryException::class, $stopped);

        $after = Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        self::assertSame(FailureReason::NOT_FOUND, $after->reason);
        self::assertSame([], $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION));
    }

    /**
     * A verification that committed before the reset took the lock keeps its
     * success, and its proof stops counting with the reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationThatCommittedFirstLosesItsProof(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $factor->update(AuthenticatorApp::FACTOR);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertNotSame([], $this->additionalProofs($user));

        Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.');

        self::assertSame([], $this->additionalProofs($user));
    }

    /**
     * Add the observer and the racer, two more connections to the test
     * database, and hash cheaply.
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
        $config->set('database.connections.racer', $config->get('database.connections.testing'));
        $config->set('hashing.bcrypt.rounds', 4);
    }

    /**
     * Skip a test on a process that cannot fork.
     *
     * @return void
     */
    private function needsAFork(): void
    {
        if (function_exists('pcntl_fork') && function_exists('posix_kill')) {
            return;
        }

        self::markTestSkipped('Overlapping changes need a process that can fork.');
    }

    /**
     * Make the first change in a transaction left open, run the second in a
     * forked worker, commit once the database reports the worker waiting on the
     * lock, and return what the worker reported once it resumed: `made`, or the
     * reason it was refused.
     *
     * @param  \Closure(): void  $first
     * @param  \Closure(): ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $second
     * @return string
     *
     * @throws \Throwable
     */
    private function holdingTheLock(\Closure $first, \Closure $second): string
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        self::assertIsArray($sockets);

        [$parent, $worker] = $sockets;

        $send = static function (string $line) use ($worker): void {
            fwrite($worker, $line . "\n");
        };

        $receive = static function () use ($parent): string {

            stream_set_timeout($parent, 30);

            $line = fgets($parent);

            self::assertIsString($line, 'The worker sent nothing.');

            return trim($line);
        };

        $connection = DB::connection();

        $connection->beginTransaction();

        $first();

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);
            $this->runInWorker($second, $send);
        }

        fclose($worker);

        try {
            self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

            $this->awaitLockWait($receive());

            $connection->commit();

            return $receive();
        } finally {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            if ($pid > 0) {
                pcntl_waitpid($pid, $status);
            }
        }
    }

    /**
     * Run the change as the second request, in the forked worker, on the
     * racer's connection, which the test never opened, so the worker shares no
     * connection with the test. The worker reports its connection's id before
     * it starts and the outcome after, then kills itself, so nothing the test
     * process set up is torn down twice.
     *
     * @param  \Closure(): ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $change
     * @param  \Closure(string): void  $send
     * @return never
     */
    private function runInWorker(\Closure $change, \Closure $send): never
    {
        try {
            config()->set('mfa.storage.connection', 'racer');

            $connection = DB::connection('racer');
            $backend    = $connection->scalar($connection->getDriverName() === 'pgsql' ? 'select pg_backend_pid()' : 'select connection_id()');

            $send(is_scalar($backend) ? (string) $backend : '');

            $send($change()->value ?? 'made');
        } catch (\Throwable $exception) {
            $send(sprintf('%s: %s', $exception::class, str_replace("\n", ' ', $exception->getMessage())));
        }

        posix_kill(getmypid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait until the database reports the worker's connection waiting for a row
     * lock, failing when it never does.
     *
     * InnoDB refreshes what `innodb_trx` reports only once nothing has read it
     * for 100 milliseconds, so looking any more often than that would keep
     * returning the first answer, and never see the worker start waiting.
     *
     * @param  string  $backend
     * @return void
     */
    private function awaitLockWait(string $backend): void
    {
        $observer = DB::connection('observer');

        $query = $observer->getDriverName() === 'pgsql'
            ? 'select count(*) from pg_stat_activity where pid = ? and wait_event_type = \'Lock\''
            : 'select count(*) from information_schema.innodb_trx where trx_mysql_thread_id = ? and trx_state = \'LOCK WAIT\'';

        for ($poll = 0; $poll < self::POLLS; $poll++) {
            $waiting = $observer->scalar($query, [(int) $backend], false);

            if (is_numeric($waiting) && (int) $waiting > 0) {
                return;
            }

            usleep(self::POLL_INTERVAL);
        }

        self::fail(sprintf('The worker never waited on the lock; it reported [%s].', $backend));
    }

    /**
     * Run the callback with the package's tables reached through the observer.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    private function asObserver(\Closure $callback): mixed
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            return $callback();
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * The proofs of additional factors the user's session still holds.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return array<int, \SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function additionalProofs(TestUser $user): array
    {
        return array_filter(
            $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION),
            static fn ($proof): bool => $proof->kind === ProofKind::ADDITIONAL_FACTOR,
        );
    }
}
