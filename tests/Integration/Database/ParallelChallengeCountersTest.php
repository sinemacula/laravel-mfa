<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Parallel guesses cannot overrun the identity's cap: the `observer` connection
 * plays a second owner. SQLite serialises all writers, so this needs a server.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeCounters::class)]
final class ParallelChallengeCountersTest extends TestCase
{
    use ArrangesEmailChallenges;

    /** @var ?\Throwable What stopped the parallel owner, if anything did. */
    private ?\Throwable $stopped = null;

    /** @var ?\SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission What the parallel owner was told, if it was. */
    private ?ChallengeAdmission $parallel = null;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $driver = DB::connection()->getDriverName();

        if (!in_array($driver, ['mysql', 'pgsql'], true)) {
            self::markTestSkipped('Parallel challenge owners are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParallelOwnerWaitsForTheReport(): void
    {
        config()->set('mfa.attempts.identity_limit', 1);

        [$user, $factor] = $this->arrangeEmailChallenges();

        $binding = $this->emailBinding($user);

        DB::transaction(function () use ($user, $factor, $binding): void {

            self::assertTrue($this->counters()->isUsable(Callers::of($user, 'web'), $factor, $binding)->isAdmitted());

            try {
                $this->parallel = $this->asObserver($user, $factor);
            } catch (DeadlockException|QueryException $exception) {
                // MySQL reports a nested transaction's timeout as a deadlock.
                $this->stopped = $exception instanceof DeadlockException ? $exception->getPrevious() : $exception;
            }

            self::assertTrue($this->counters()->report(Callers::of($user, 'web'), $factor, $binding, false)->isFailed());
        });

        self::assertNull($this->parallel);
        self::assertInstanceOf(QueryException::class, $this->stopped);
        self::assertSame(FailureReason::LOCKED, $this->asObserver($user, $factor)->reason);
        self::assertSame(1, Factor::query()->findOrFail($factor->id)->getConsecutiveFailures());
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
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Throwable
     */
    private function asObserver(TestUser $user, Factor $factor): ChallengeAdmission
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            $stored = Factor::query()->findOrFail($factor->id);

            $caller = Callers::of($user, 'web');

            return DB::connection('observer')->transaction(fn (): ChallengeAdmission => $this->counters()->isUsable($caller, $stored, $this->emailBinding($user)));
        } finally {
            config()->set('mfa.storage.connection', null);
        }
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
}
