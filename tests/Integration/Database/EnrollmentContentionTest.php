<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\RecordingFactorDriver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * Two first confirmations race on separate connections to one SQLite file;
 * `observer` plays a concurrent request that never waits for a lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentConfirmer::class)]
final class EnrollmentContentionTest extends TestCase
{
    use MigratesTheStorageConnection;

    /** @var string SQLite file holding the package's tables. */
    private string $database = '';

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
     * The second cannot start while the first holds the lock, then is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoFirstConfirmationsOneCountsAsFirst(): void
    {
        $identity = new NonEloquentIdentity('person-1', mfaEnabled: true);
        $store    = $this->container()->make(ProofStore::class);

        Auth::setUser($identity);

        $store->begin($identity, 'web', 'sign-in-1');
        $store->record($identity, SignInProofs::of($identity)->password(60));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        Mfa::extend('other', fn (): RecordingFactorDriver => new RecordingFactorDriver);

        $totp  = Mfa::startEnrollment(Callers::current(), EnrollmentRequest::totp('person@example.test'));
        $other = Mfa::startEnrollment(Callers::current(), EnrollmentRequest::of('other'));
        $code  = AuthenticatorApp::code(Factor::query()->whereKey($totp->factor?->id)->sole());

        self::assertTrue($totp->hasStarted());
        self::assertTrue($other->hasStarted());

        $grant = (string) $other->grant?->reveal();
        $tried = false;

        Enrollment::deleting(function () use ($grant, &$tried): void {

            if ($tried) {
                return;
            }

            $tried = true;

            $this->assertCompetingConfirmationIsLockedOut($grant);
        });

        $first = Mfa::confirmEnrollment(Callers::current(), (string) $totp->grant?->reveal(), $code);

        self::assertTrue($tried);
        self::assertTrue($first->isConfirmed());
        self::assertCount(10, $first->recoveryCodes);

        $second = Mfa::confirmEnrollment(Callers::current(), $grant, 'correct');

        self::assertSame(FailureReason::NOT_FRESH, $second->reason);
        self::assertSame(1, Factor::query()->where('status', 'confirmed')->count());
        self::assertSame(10, RecoveryCode::query()->count());
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

        $this->database = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mfa-enrollments-' . Str::lower((string) Str::ulid()) . '.sqlite';

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

        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.storage.connection', 'storage');
        $config->set('mfa.applications.web', [
            'types'          => ['totp', 'other'],
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * @param  string  $grant
     * @return void
     */
    private function assertCompetingConfirmationIsLockedOut(string $grant): void
    {
        Config::set('mfa.storage.connection', 'observer');

        try {
            Mfa::confirmEnrollment(Callers::current(), $grant, 'correct');

            self::fail('A confirmation competing for the lock was expected to be locked out.');
        } catch (QueryException $exception) {
            self::assertStringContainsString('locked', $exception->getMessage());
        } finally {
            Config::set('mfa.storage.connection', 'storage');
        }

        self::assertSame(0, DB::connection('observer')->transactionLevel());
    }
}
