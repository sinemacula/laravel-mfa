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
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Parallel guesses cannot overrun a cap: the `observer` connection plays a
 * concurrent request. SQLite serialises all writers, so this needs a server.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptService::class)]
#[CoversClass(AttemptStore::class)]
final class ParallelAttemptsTest extends TestCase
{
    /** @var string Both attempts come from this address. */
    private const string IP = '192.0.2.1';

    /** @var ?\Throwable What stopped the parallel attempt, if anything did. */
    private ?\Throwable $stopped = null;

    /** @var ?\SineMacula\Laravel\Mfa\Attempts\AttemptOutcome How the parallel attempt ended, if it did. */
    private ?AttemptOutcome $parallel = null;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $driver = DB::connection()->getDriverName();

        if (!in_array($driver, ['mysql', 'pgsql'], true)) {
            self::markTestSkipped('Parallel attempts are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * With a limit of one, only one guess reaches a driver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParallelGuessForTheIdentityWaitsForTheCount(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $user   = $this->user('first@example.com');
        $factor = $this->factor($user);

        $first = $this->service()->attempt(new Attempt($user, $factor, Purpose::SIGN_IN), function () use ($user, $factor): bool {

            try {
                $this->parallel = $this->asObserver($user, $factor->id, null);
            } catch (QueryException $exception) {
                $this->stopped = $exception;
            }

            return false;
        });

        $second = $this->asObserver($user, $factor->id, null);

        self::assertTrue($first->isFailed());
        self::assertNull($this->parallel);
        self::assertInstanceOf(QueryException::class, $this->stopped);
        self::assertTrue($second->isRefused());
        self::assertSame(AttemptScope::FACTOR, $second->lockout?->scope);
        self::assertSame(1, Factor::query()->findOrFail($factor->id)->getConsecutiveFailures());
    }

    /**
     * The guess is throttled without reaching its driver or waiting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParallelGuessFromTheAddressFindsTheSlotTaken(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $first       = $this->user('first@example.com');
        $other       = $this->user('other@example.com');
        $otherFactor = $this->factor($other);

        $factor = $this->factor($first);

        $outcome = $this->service()->throttled(self::IP, fn (): AttemptOutcome => $this->service()->attempt(
            new Attempt($first, $factor, Purpose::SIGN_IN),
            function () use ($other, $otherFactor): bool {

                $this->parallel = $this->asObserver($other, $otherFactor->id, self::IP);

                return false;
            },
        ));

        self::assertTrue($outcome->isFailed());
        self::assertInstanceOf(AttemptOutcome::class, $this->parallel);
        self::assertTrue($this->parallel->isRefused());
        self::assertSame(AttemptScope::IP, $this->parallel->lockout?->scope);
    }

    /**
     * The count is one upsert, so no gap lock blocks the second identity's row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstFailuresOfTwoIdentitiesDoNotWaitOnEachOther(): void
    {
        $connection = DB::connection();

        $connection->statement($connection->getDriverName() === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');

        $first    = $this->user('first@example.com');
        $other    = $this->user('other@example.com');
        $now      = CarbonImmutable::now()->getTimestamp();
        $observer = DB::connection('observer');

        $observer->beginTransaction();

        try {
            config()->set('mfa.storage.connection', 'observer');

            $this->container()->make(AttemptStore::class)->record(
                $this->container()->make(AttemptKeys::class)->identity($other::class, (string) $other->id),
                AttemptScope::IDENTITY,
                $now,
                $now + 900,
            );

            config()->set('mfa.storage.connection', null);

            $outcome = $this->service()->attempt(new Attempt($first, null, Purpose::SIGN_IN), static fn (): bool => false);
        } finally {
            config()->set('mfa.storage.connection', null);

            $observer->rollBack();
        }

        self::assertTrue($outcome->isFailed());
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
     * The attempt's verification must never run.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $factorId
     * @param  ?string  $ip
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \Throwable
     */
    private function asObserver(TestUser $user, string $factorId, ?string $ip): AttemptOutcome
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            return $this->service()->throttled($ip, fn (): AttemptOutcome => $this->service()->attempt(
                new Attempt($user, Factor::query()->findOrFail($factorId), Purpose::SIGN_IN),
                static function (): bool {
                    throw new MidRotationFailureException('A parallel guess must not reach its driver.');
                },
            ));
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factor(TestUser $user): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(string $email): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
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
