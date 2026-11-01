<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Parallel guesses cannot overrun a cap, on MySQL and PostgreSQL.
 *
 * The package's tables live on the default connection, which a second
 * connection to the same database, `observer`, stands in for a concurrent
 * request on, with a lock timeout of a second. While one attempt runs its
 * verification, a parallel attempt for the same identity cannot read the
 * counts: it waits for the identity's state lock and times out. Once the first
 * attempt has counted its failure, the parallel one finds the lockout it
 * applied. A parallel attempt from the same address for another identity finds
 * the slot the first attempt took, and is throttled without waiting.
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
final class ParallelAttemptsTest extends TestCase
{
    /** @var string The address both attempts come from. */
    private const string IP = '192.0.2.1';

    /** @var ?\Throwable What stopped the parallel attempt, if anything did. */
    private ?\Throwable $stopped = null;

    /** @var ?\SineMacula\Laravel\Mfa\Attempts\AttemptOutcome How the parallel attempt ended, if it did. */
    private ?AttemptOutcome $parallel = null;

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
            self::markTestSkipped('Parallel attempts are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * A parallel guess for the same identity waits for the first guess's count
     * and lockout, so with a limit of one, only one guess reaches a driver.
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
     * A parallel guess from the same address for another identity finds the
     * slot the first guess took, so with a limit of one it is throttled without
     * reaching its driver or waiting for the first.
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

        $outcome = $this->service()->attempt(new Attempt($first, $this->factor($first), Purpose::SIGN_IN, self::IP), function () use ($other, $otherFactor): bool {

            $this->parallel = $this->asObserver($other, $otherFactor->id, self::IP);

            return false;
        });

        self::assertTrue($outcome->isFailed());
        self::assertInstanceOf(AttemptOutcome::class, $this->parallel);
        self::assertTrue($this->parallel->isRefused());
        self::assertSame(AttemptScope::IP, $this->parallel->lockout?->scope);
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
     * Make an attempt on the observer, as a concurrent request would, whose
     * verification must never run.
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
            return $this->service()->attempt(
                new Attempt($user, Factor::query()->findOrFail($factorId), Purpose::SIGN_IN, $ip),
                static function (): bool {
                    throw new MidRotationFailureException('A parallel guess must not reach its driver.');
                },
            );
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * Create a confirmed TOTP factor for the user.
     *
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
     * Create a test user.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(string $email): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
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
