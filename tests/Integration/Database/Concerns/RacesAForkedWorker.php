<?php

declare(strict_types = 1);

namespace Tests\Integration\Database\Concerns;

use Illuminate\Support\Facades\DB;

/**
 * Runs a change in a forked worker on the `racer` connection while the test's
 * transaction holds the lock it waits on; `observer` watches it wait.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RacesAForkedWorker
{
    /** @var int Wait between polls, in microseconds. */
    private const int POLL_INTERVAL = 150000;

    /** @var int Polls for the worker waiting on the lock. */
    private const int POLLS = 400;

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
     * Ends the first change once the worker waits on its lock, committing it
     * unless told not to, and returns `made` or the worker's refusal reason.
     *
     * @param  \Closure(): void  $first
     * @param  \Closure(): ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $second
     * @param  bool  $commit
     * @return string
     *
     * @throws \Throwable
     */
    private function holdingTheLock(\Closure $first, \Closure $second, bool $commit = true): string
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

            $commit ? $connection->commit() : $connection->rollBack();

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
     *
     * @throws \LogicException
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

        throw new \LogicException('The worker outlived its own kill.');
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
}
