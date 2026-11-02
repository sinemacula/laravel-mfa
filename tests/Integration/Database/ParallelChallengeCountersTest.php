<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * A challenge owner's parallel guesses cannot overrun the identity's cap, on
 * MySQL and PostgreSQL.
 *
 * The package's tables live on the default connection, which a second
 * connection to the same database, `observer`, stands in for a concurrent
 * challenge owner on, with a lock timeout of a second. While one owner holds
 * its transaction between asking whether the factor may be challenged and
 * reporting the outcome, a parallel owner asking about the same identity waits
 * for the identity's state lock and times out; once the first has reported the
 * failure that locks the identity, the parallel one finds the lockout.
 *
 * SQLite serialises every writer on the whole file, so these tests run on the
 * server databases only.
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
            self::markTestSkipped('Parallel challenge owners are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * A parallel owner waits for the first owner's report, and then finds the
     * identity it locked.
     *
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

            self::assertTrue($this->counters()->isUsable($user, $factor, $binding)->isAdmitted());

            try {
                $this->parallel = $this->asObserver($user, $factor);
            } catch (QueryException $exception) {
                $this->stopped = $exception;
            }

            self::assertTrue($this->counters()->report($user, $factor, $binding, false)->isFailed());
        });

        self::assertNull($this->parallel);
        self::assertInstanceOf(QueryException::class, $this->stopped);
        self::assertSame(FailureReason::LOCKED, $this->asObserver($user, $factor)->reason);
        self::assertSame(1, Factor::query()->findOrFail($factor->id)->getConsecutiveFailures());
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
     * Ask about the factor on the observer, inside a transaction of its own, as
     * a concurrent owner would.
     *
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

            return DB::connection('observer')->transaction(fn (): ChallengeAdmission => $this->counters()->isUsable($user, $stored, $this->emailBinding($user)));
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * The counters under test.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function counters(): ChallengeCounters
    {
        return $this->container()->make(ChallengeCounters::class);
    }
}
