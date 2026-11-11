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
 * Overlapping removals and resets, with `observer` or a forked worker as the
 * concurrent request. SQLite serialises all writers, so this needs a server.
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

    /** @var int Wait between polls, in microseconds. */
    private const int POLL_INTERVAL = 150000;

    /** @var int Polls for the worker waiting on the lock. */
    private const int POLLS = 400;

    /**
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
     * The revoker advances nothing, so only the last factor check can refuse
     * the worker.
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

        // A type no application enables: a proof that covers neither factor.
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
        self::assertSame([], $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION, self::SESSION));
    }

    /**
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
     * Commits the first change once the worker waits on its lock, and returns
     * `made` or the worker's refusal reason.
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
     * Uses the racer connection the test never opened, and kills itself so
     * nothing the test set up is torn down twice.
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

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * InnoDB refreshes `innodb_trx` only after 100ms unread, so poll no faster.
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
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return array<int, \SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function additionalProofs(TestUser $user): array
    {
        return array_filter(
            $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION, self::SESSION),
            static fn ($proof): bool => $proof->kind === ProofKind::ADDITIONAL_FACTOR,
        );
    }
}
