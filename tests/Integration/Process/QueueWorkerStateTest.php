<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Identities\TestUser;
use Tests\Integration\Process\Fixtures\ActsForAPersonJob;
use Tests\Integration\Process\Fixtures\JobObservations;
use Tests\TestCase;

/**
 * One worker runs jobs for different people, clearing the guards and session in
 * `Queue::before()` as the operations guide documents; Laravel clears neither.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(MfaServiceProvider::class)]
#[CoversClass(FactorService::class)]
final class QueueWorkerStateTest extends TestCase
{
    /** @var string Alice's email factor destination. */
    private const string ADDRESS = 'alice@example.test';

    /** @var bool Whether the session is cleared before each job. */
    private bool $clearsTheSession = true;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('jobs', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('queue')->index();
            $blueprint->longText('payload');
            $blueprint->unsignedTinyInteger('attempts');
            $blueprint->unsignedInteger('reserved_at')->nullable();
            $blueprint->unsignedInteger('available_at');
            $blueprint->unsignedInteger('created_at');
        });

        $this->container()->instance(JobObservations::class, new JobObservations);

        Queue::before(function (JobProcessing $event): void {

            if ($event->connectionName === 'sync') {
                return;
            }

            Auth::forgetGuards();

            if (!$this->clearsTheSession) {
                return;
            }

            Session::flush();
        });
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('jobs');

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testEachJobSeesOnlyItsOwnIdentitysState(): void
    {
        $alice   = $this->person(self::ADDRESS);
        $bob     = $this->person('bob@example.test');
        $hers    = $this->factorOf($alice, AuthenticatorApp::FACTOR);
        $his     = $this->factorOf($bob, AuthenticatorApp::FACTOR);
        $hersKey = $alice->id;
        $hisKey  = $bob->id;

        dispatch(new ActsForAPersonJob('alice', $hersKey, renames: $hers->id));
        dispatch(new ActsForAPersonJob('nobody'));
        dispatch(new ActsForAPersonJob('bob', $hisKey));
        dispatch(new ActsForAPersonJob('failing', $hisKey, fails: true));
        dispatch(new ActsForAPersonJob('nobody-again'));
        dispatch(new ActsForAPersonJob('alice-again', $hersKey));

        $this->work();

        self::assertSame(['alice', 'nobody', 'bob', 'nobody-again', 'alice-again'], array_column($this->seen(), 'job'));

        [$first, $nobody, $second, $nobodyAgain, $firstAgain] = $this->seen();

        self::assertSame($hersKey, $first['identity']);
        self::assertSame([$hers->id], $first['factors']);
        self::assertSame(0, $first['proofs']);
        self::assertTrue($first['changed']);
        self::assertSame('Renamed by alice', Factor::query()->whereKey($hers->id)->value('label'));

        foreach ([$nobody, $nobodyAgain] as $empty) {
            self::assertNull($empty['identity']);
            self::assertSame([], $empty['factors']);
            self::assertSame(0, $empty['proofs']);
            self::assertFalse($empty['changed']);
        }

        self::assertSame($hisKey, $second['identity']);
        self::assertSame([$his->id], $second['factors']);
        self::assertSame(0, $second['proofs']);

        self::assertSame($hersKey, $firstAgain['identity']);
        self::assertSame([$hers->id], $firstAgain['factors']);
        self::assertSame(0, $firstAgain['proofs']);

        self::assertNull(Factor::query()->whereKey($his->id)->value('label'));
    }

    /**
     * No sign-in event forgets the proof; clearing the session does.
     *
     * @return void
     */
    public function testAProofDoesNotOutliveTheJobThatMadeIt(): void
    {
        self::assertSame([1, 0, 0], $this->proofsAcrossJobs());
    }

    /**
     * Why the guide clears the session: the person's next job reads the proof.
     *
     * @return void
     */
    public function testAProofLivesInAWorkersSessionUntilItIsCleared(): void
    {
        $this->clearsTheSession = false;

        self::assertSame([1, 1, 0], $this->proofsAcrossJobs());
    }

    /**
     * A code never falls through to the fail-closed default sender.
     *
     * @return void
     */
    public function testAFakeSenderInstalledAtBootSurvivesEveryJob(): void
    {
        $alice = $this->person(self::ADDRESS);
        $email = $this->factorOf($alice, ['type' => 'email', 'destination' => self::ADDRESS]);
        $key   = $alice->id;

        dispatch(new ActsForAPersonJob('first', $key));
        dispatch(new ActsForAPersonJob('sender', $key, sendsTo: $email->id));

        $this->work();

        self::assertSame(['first', 'sender'], array_column($this->seen(), 'job'));
        $mailbox = $this->container()->make(EmailSender::class);

        self::assertInstanceOf(FakeEmailSender::class, $mailbox);
        self::assertNotNull($mailbox->lastCodeTo(self::ADDRESS));
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

        FakeEmailSender::fake($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('auth.defaults.guard', 'web');
        $config->set('auth.providers.users', ['driver' => 'eloquent', 'model' => TestUser::class]);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $config->set('session.driver', 'array');
        $config->set('logging.default', 'null');
        $config->set('queue.default', 'database');
        $config->set('queue.failed.driver', 'null');
        $config->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
        $config->set('mfa.applications.web', [
            'types'        => ['totp', 'email'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * Proofs seen by a verifying job, then the same person's and another's job.
     *
     * @return list<int>
     */
    private function proofsAcrossJobs(): array
    {
        $alice = $this->person(self::ADDRESS);
        $bob   = $this->person('bob@example.test');
        $hers  = $this->factorOf($alice, AuthenticatorApp::FACTOR);

        $this->factorOf($bob, AuthenticatorApp::FACTOR);

        dispatch(new ActsForAPersonJob('verifies', $alice->id, verifies: $hers->id, code: AuthenticatorApp::code($hers)));
        dispatch(new ActsForAPersonJob('same person', $alice->id, signsIn: false));
        dispatch(new ActsForAPersonJob('another person', $bob->id, signsIn: false));

        $this->work();

        self::assertSame(['verifies', 'same person', 'another person'], array_column($this->seen(), 'job'));

        return array_column($this->seen(), 'proofs');
    }

    /**
     * No memory limit: the suite may already exceed a worker's default and stop
     * the loop before the first job.
     *
     * @return void
     */
    private function work(): void
    {
        $worker = $this->container()->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $options = new WorkerOptions(memory: PHP_INT_MAX, sleep: 0, maxTries: 1, stopWhenEmpty: true);

        self::assertSame(Worker::EXIT_SUCCESS, self::keepingSignalHandlers(static fn (): mixed => $worker->daemon('database', 'default', $options)));
        self::assertSame(0, DB::table('jobs')->count());
    }

    /**
     * Restores the worker's signal handlers so Ctrl-C still stops the test.
     *
     * @param  \Closure(): mixed  $callback
     * @return mixed
     */
    private static function keepingSignalHandlers(\Closure $callback): mixed
    {
        if (!function_exists('pcntl_signal_get_handler')) {
            return $callback();
        }

        $signals  = [SIGQUIT, SIGTERM, SIGINT, SIGUSR2, SIGCONT];
        $handlers = array_map(pcntl_signal_get_handler(...), $signals);
        $async    = pcntl_async_signals();

        try {
            return $callback();
        } finally {
            foreach ($signals as $index => $signal) {
                pcntl_signal($signal, $handlers[$index]);
            }

            pcntl_async_signals($async);
        }
    }

    /**
     * @return list<array{job: string, identity: mixed, factors: list<string>, proofs: int, changed: bool}>
     */
    private function seen(): array
    {
        return $this->container()->make(JobObservations::class)->seen;
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(string $email): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorOf(TestUser $person, array $attributes): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => (string) $person->id,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => 'web',
            ...$attributes,
        ]);
    }
}
