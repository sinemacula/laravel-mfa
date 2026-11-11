<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * Recovery codes, their transactions and the identity's lock all use the
 * `secondary` storage connection while the identity stays on the default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
final class StorageConnectionRecoveryCodesTest extends TestCase
{
    use MigratesTheStorageConnection;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testGenerationWritesToTheStorageConnection(): void
    {
        $user = $this->loginUser();

        $codes = $this->codes()->generate($user, 'web');

        self::assertCount(10, $codes);
        self::assertSame('secondary', (new RecoveryCode)->getConnectionName());
        self::assertSame(10, DB::connection('secondary')->table('mfa_recovery_codes')->where('authenticatable_id', (string) $user->id)->count());
        self::assertSame(1, DB::connection('secondary')->table('mfa_identity_states')->count());

        self::assertSame(0, $this->countOnTheDefaultConnection('mfa_recovery_codes', (string) $user->id));
        self::assertSame(0, $this->countOnTheDefaultConnection('mfa_identity_states', (string) $user->id));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRedemptionRunsOnTheStorageConnection(): void
    {
        $code = $this->codes()->generate($this->loginUser(), 'web')[0]->reveal();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($code))->isVerified());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($code))->isFailed());
        self::assertSame(1, DB::connection('secondary')->table('mfa_recovery_codes')->whereNotNull('used_at')->count());
        self::assertSame(0, DB::connection('secondary')->transactionLevel());
        self::assertSame(9, Mfa::recoveryCodeStatus(Callers::current())?->remaining);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReplacementRollsBackOnTheStorageConnection(): void
    {
        $user  = $this->loginUser();
        $prior = $this->codes()->generate($user, 'web');
        $seen  = 0;

        RecoveryCode::creating(static function () use (&$seen): void {
            if (++$seen === 3) {
                throw new MidRotationFailureException('mid-replacement failure');
            }
        });

        try {
            $this->codes()->generate($user, 'web');
            self::fail('Expected the replacement to fail partway through.');
        } catch (MidRotationFailureException $exception) {
            self::assertSame('mid-replacement failure', $exception->getMessage());
        }

        self::assertSame(0, DB::connection('secondary')->transactionLevel());
        self::assertSame(10, RecoveryCode::query()->where('authenticatable_id', (string) $user->id)->whereNull('replaced_at')->count());
        self::assertSame(1, Mfa::recoveryCodeStatus(Callers::current())?->generation);
        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($prior[9]->reveal()))->isVerified());
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

        $config->set('database.connections.secondary', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('mfa.storage.connection', 'secondary');
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.applications.web', [
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function codes(): RecoveryCodeService
    {
        return $this->container()->make(RecoveryCodeService::class);
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function loginUser(): TestUser
    {
        $user = TestUser::query()->create([
            'email'       => 'rotation@example.test',
            'mfa_enabled' => true,
        ]);

        Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        Auth::login($user);

        return $user;
    }

    /**
     * A shared test database may hold the table, so count only these rows.
     *
     * @param  string  $table
     * @param  string  $identifier
     * @return int
     */
    private function countOnTheDefaultConnection(string $table, string $identifier): int
    {
        if (!Schema::connection('testing')->hasTable($table)) {
            return 0;
        }

        return DB::connection('testing')->table($table)
            ->where('authenticatable_type', (new TestUser)->getMorphClass())
            ->where('authenticatable_id', $identifier)
            ->count();
    }
}
