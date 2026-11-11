<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\TestCase;

/**
 * Racing TOTP requests record the step once: the database checks it against the
 * committed row, whatever the losing request's stale copy says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TotpDriver::class)]
#[CoversTrait(ActsAsFactor::class)]
final class TotpReplayRaceTest extends TestCase
{
    /** @var int Frozen time, 15 seconds into step 60000000. */
    private const int NOW = 1800000015;

    /** @var int Step the frozen time falls in. */
    private const int STEP = 60000000;

    /** @var int Wait between polls, in microseconds. */
    private const int POLL_INTERVAL = 150000;

    /** @var int Polls for the worker waiting on the row. */
    private const int POLLS = 400;

    /** @var string Second request's connection; shares `testing` on in-memory SQLite. */
    private string $racer = 'testing';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(CarbonImmutable::createFromTimestamp(self::NOW));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyOneOfTwoRequestsWithTheSameCodePasses(): void
    {
        $factor = $this->storedFactor();

        [$first, $second] = $this->race($factor, static fn (Factor $copy): string => AuthenticatorApp::code($copy));

        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame(self::STEP, $this->storedStep($factor));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithAnEarlierStepLosesToALaterOne(): void
    {
        $factor = $this->storedFactor();

        $later   = static fn (Factor $copy): string => AuthenticatorApp::code($copy, 1);
        $current = static fn (Factor $copy): string => AuthenticatorApp::code($copy);

        [$first, $second] = $this->race($factor, $later, $current);

        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame(self::STEP + 1, $this->storedStep($factor));
    }

    /**
     * The forked second request waits on the uncommitted row, then is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoOverlappingRequestsWithTheSameCodeOnlyOnePasses(): void
    {
        if ($this->racer === 'testing' || !function_exists('pcntl_fork') || !function_exists('posix_kill')) {
            self::markTestSkipped('Overlapping requests need a database that serves several connections, and a process that can fork.');
        }

        $factor     = $this->storedFactor();
        $code       = AuthenticatorApp::code($factor);
        $driver     = $this->driver();
        $connection = DB::connection();
        $sockets    = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

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

        $connection->beginTransaction();

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify(Factor::query()->findOrFail($factor->id), $code, self::binding()));

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);
            $this->verifyInWorker($driver, $factor->id, $code, $send);
        }

        fclose($worker);

        try {
            self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

            $this->awaitLockWait($receive());

            $connection->commit();

            $second = $receive();
        } finally {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            if ($pid > 0) {
                pcntl_waitpid($pid, $status);
            }
        }

        self::assertSame('refused', $second);
        self::assertSame(self::STEP, $this->storedStep($factor));
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

        $testing = $config->get('database.connections.testing');

        if (!is_array($testing) || ($testing['driver'] ?? null) === 'sqlite') {
            return;
        }

        $config->set('database.connections.racer', $testing);
        $config->set('database.connections.observer', $testing);

        $this->racer = 'racer';
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(): ProofBinding
    {
        return new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::SIGN_IN);
    }

    /**
     * The second request reads the factor before the first verifies.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  \Closure(\SineMacula\Laravel\Mfa\Models\Factor): string  $firstCode
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Models\Factor): string  $secondCode
     * @return array{0: bool, 1: bool}
     *
     * @throws \Throwable
     */
    private function race(Factor $factor, \Closure $firstCode, ?\Closure $secondCode = null): array
    {
        $driver = $this->driver();
        $racer  = DB::connection($this->racer);

        $racer->beginTransaction();

        try {
            $second = Factor::on($this->racer)->findOrFail($factor->id);

            self::assertNull($second->getLastAcceptedStep());

            $first = Factor::query()->findOrFail($factor->id);

            $firstPassed  = $driver->verify($first, $firstCode($first), self::binding())                    === CodeCheck::ACCEPTED;
            $secondPassed = $driver->verify($second, ($secondCode ?? $firstCode)($second), self::binding()) === CodeCheck::ACCEPTED;

            $racer->commit();
        } catch (\Throwable $exception) {
            $racer->rollBack();

            throw $exception;
        }

        return [$firstPassed, $secondPassed];
    }

    /**
     * Uses the racer connection the test never opened, and kills itself so
     * nothing the test set up is torn down twice.
     *
     * @param  \SineMacula\Laravel\Mfa\Drivers\TotpDriver  $driver
     * @param  string  $id
     * @param  string  $code
     * @param  \Closure(string): void  $send
     * @return never
     */
    private function verifyInWorker(TotpDriver $driver, string $id, string $code, \Closure $send): never
    {
        try {
            $connection = DB::connection($this->racer);
            $copy       = Factor::on($this->racer)->findOrFail($id);

            $backend = $connection->scalar($connection->getDriverName() === 'pgsql' ? 'select pg_backend_pid()' : 'select connection_id()');

            $send(is_scalar($backend) ? (string) $backend : '');
            $send($driver->verify($copy, $code, self::binding()) === CodeCheck::ACCEPTED ? 'passed' : 'refused');
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

        self::fail(sprintf('The worker never waited on the row; it reported [%s].', $backend));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function driver(): TotpDriver
    {
        return new TotpDriver(new TotpSettings($this->container()->make(Repository::class)));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function storedFactor(): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
            'status'               => 'confirmed',
        ]);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?int
     *
     * @phpstan-impure
     */
    private function storedStep(Factor $factor): ?int
    {
        $step = DB::table('mfa_factors')->where('id', $factor->id)->value('last_accepted_step');

        if ($step === null) {
            return null;
        }

        self::assertIsNumeric($step);

        return (int) $step;
    }
}
