<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Codes\RecordingCodeDriver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * Delivered codes under competing requests; `observer` plays a concurrent
 * request on the same SQLite file that never waits for a lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(DeliveredCodes::class)]
final class DeliveredCodeContentionTest extends TestCase
{
    use MigratesTheStorageConnection;

    /** @var string Identity the codes are sent to. */
    private const string IDENTITY_KEY = 'person-1';

    /** @var string Code the engine draws. */
    private const string CODE = '123456';

    /** @var string SQLite file holding the package's tables. */
    private string $database = '';

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();

        $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:00'));

        $this->container()->instance(DeliveredCodes::class, new DeliveredCodes($this->container()->make(Repository::class), static fn (int $length): string => self::CODE));

        Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => self::IDENTITY_KEY,
            'type'                 => 'email',
            'destination'          => 'ada@example.test',
            'status'               => 'confirmed',
        ]);
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        if ($this->database === '' || !is_file($this->database)) {
            return;
        }

        unlink($this->database);
    }

    /**
     * Once the first commits, the factor's cap refuses the competing send.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASendHoldsTheIdentityLockUntilItsCodeIsDelivered(): void
    {
        Config::set('mfa.codes.factor_send_limit', 1);

        $driver         = new RecordingCodeDriver;
        $driver->onSend = function (): void {
            $this->assertCompetingSendIsLockedOut();
        };

        self::assertTrue($this->service()->send(self::identity(), self::factor(), self::binding('session-a'), $driver)->wasSent());
        self::assertCount(1, $driver->delivered);

        $competing = $this->asObserver(fn () => $this->service()->send(self::identity(), self::factor(), self::binding('session-b'), new RecordingCodeDriver));

        self::assertSame(FailureReason::SENDING_CAPPED, $competing->reason);
        self::assertSame(3600, $competing->retryAfter);
    }

    /**
     * The first check to use the code wins; the earlier reader finds it spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoInterleavedChecksOnlyOneIsAccepted(): void
    {
        $challenge = (string) $this->service()->send(self::identity(), self::factor(), self::binding('session-a'), new RecordingCodeDriver)->challengeId;
        $competing = null;
        $done      = false;

        Code::retrieved(function () use (&$done, &$competing, $challenge): void {

            if ($done) {
                return;
            }

            $done      = true;
            $competing = $this->asObserver(fn (): CodeCheck => $this->service()->check(self::factor(), self::binding('session-a'), self::CODE, $challenge));
        });

        $first = $this->service()->check(self::factor(), self::binding('session-a'), self::CODE, $challenge);

        self::assertSame(CodeCheck::ACCEPTED, $competing);
        self::assertSame(CodeCheck::SPENT, $first);
        self::assertSame(1, DB::connection('storage')->table('mfa_codes')->value('attempts'));
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

        $this->database = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mfa-codes-' . Str::lower((string) Str::ulid()) . '.sqlite';

        touch($this->database);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        foreach (['storage', 'observer'] as $name) {
            $config->set('database.connections.' . $name, [
                'driver'       => 'sqlite',
                'database'     => $this->database,
                'prefix'       => '',
                'busy_timeout' => 0,
            ]);
        }

        $config->set('mfa.storage.connection', 'storage');
    }

    /**
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     */
    private function asObserver(\Closure $callback): mixed
    {
        Config::set('mfa.storage.connection', 'observer');

        try {
            return $callback();
        } finally {
            Config::set('mfa.storage.connection', 'storage');
        }
    }

    /**
     * @return void
     */
    private function assertCompetingSendIsLockedOut(): void
    {
        try {
            $this->asObserver(fn () => $this->service()->send(self::identity(), self::factor(), self::binding('session-b'), new RecordingCodeDriver));

            self::fail('A competing send must not take the lock while another send holds it.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertSame(5, $exception->errorInfo[1] ?? null, 'SQLite answers with SQLITE_BUSY.');
        }

        // The refused statement, kept alive by the trace, holds a read lock.
        unset($exception);

        DB::purge('observer');

        gc_collect_cycles();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Codes\CodeService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): CodeService
    {
        return $this->container()->make(CodeService::class);
    }

    /**
     * @return \Tests\Fixtures\Identities\NonEloquentIdentity
     */
    private static function identity(): NonEloquentIdentity
    {
        return new NonEloquentIdentity(self::IDENTITY_KEY);
    }

    /**
     * Read on whichever connection the package is pointed at.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private static function factor(): Factor
    {
        return Factor::query()->sole();
    }

    /**
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(string $session): ProofBinding
    {
        return new ProofBinding(NonEloquentIdentity::class, self::IDENTITY_KEY, 'web', $session, Purpose::SIGN_IN);
    }
}
