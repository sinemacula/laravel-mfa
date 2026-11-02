<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Drivers\RecordingFactorDriver;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * Two first confirmations racing, on MySQL and PostgreSQL.
 *
 * The package's tables live on the default connection, which a second
 * connection to the same database, `observer`, stands in for a concurrent
 * request on, with a lock timeout of a second. While one confirmation holds the
 * identity's factor state lock, a parallel one cannot read what it would decide
 * on: it waits for the lock and times out. Once the first has committed, the
 * parallel one finds a confirmed factor, so it is refused: exactly one counts
 * as first, and recovery codes are issued once.
 *
 * SQLite serialises every writer on the whole file, so these tests run on the
 * server databases only; `EnrollmentContentionTest` proves the same on a shared
 * SQLite file, and the feature tests on one connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentConfirmer::class)]
final class EnrollmentRaceTest extends TestCase
{
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
            self::markTestSkipped('Concurrent first confirmations are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * Of two first confirmations of two pending factors, the second waits for
     * the first to commit, then is refused: one counts as first, and the codes
     * are issued once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoFirstConfirmationsOneCountsAsFirst(): void
    {
        $this->signIn();

        $totp  = Mfa::startEnrollment(EnrollmentRequest::totp('person@example.test'));
        $email = Mfa::startEnrollment(EnrollmentRequest::of('other'));

        self::assertTrue($totp->hasStarted());
        self::assertTrue($email->hasStarted());

        $grant   = (string) $totp->grant?->reveal();
        $other   = (string) $email->grant?->reveal();
        $code    = self::codeOf($totp);
        $stopped = null;

        Enrollment::deleting(function () use ($other, &$stopped): void {

            if ($stopped !== null) {
                return;
            }

            $stopped = false;

            try {
                $this->asObserver(static fn (): EnrollmentConfirmation => Mfa::confirmEnrollment($other, 'correct'));
            } catch (QueryException $exception) {
                $stopped = $exception;
            }
        });

        $first = Mfa::confirmEnrollment($grant, $code);

        self::assertTrue($first->isConfirmed());
        self::assertCount(10, $first->recoveryCodes);
        self::assertInstanceOf(QueryException::class, $stopped);

        $second = Mfa::confirmEnrollment($other, 'correct');

        self::assertSame(FailureReason::NOT_FRESH, $second->reason);
        self::assertSame([], $second->recoveryCodes);
        self::assertSame(1, Factor::query()->where('status', 'confirmed')->count());
        self::assertSame(10, RecoveryCode::query()->count());
    }

    /**
     * While a start holds the identity's lock, a parallel start waits for it; it
     * then discards what the first made, so one pending factor of the type is
     * left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParallelStartWaitsAndThenReplaces(): void
    {
        $this->signIn();

        $stopped = null;

        Enrollment::creating(function () use (&$stopped): void {

            if ($stopped !== null) {
                return;
            }

            $stopped = false;

            try {
                $this->asObserver(static fn (): EnrollmentStart => Mfa::startEnrollment(EnrollmentRequest::totp('person@example.test')));
            } catch (QueryException $exception) {
                $stopped = $exception;
            }
        });

        self::assertTrue(Mfa::startEnrollment(EnrollmentRequest::totp('person@example.test'))->hasStarted());
        self::assertInstanceOf(QueryException::class, $stopped);
        self::assertTrue(Mfa::startEnrollment(EnrollmentRequest::totp('person@example.test'))->hasStarted());
        self::assertSame(1, Factor::query()->count());
        self::assertSame(1, Enrollment::query()->count());
    }

    /**
     * Add the observer, a second connection to the test database, enable the
     * types and hash cheaply.
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
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.applications.web', [
            'types'          => ['totp', 'other'],
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * The code the factor's authenticator app shows now.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @return string
     */
    private static function codeOf(EnrollmentStart $start): string
    {
        return AuthenticatorApp::code(Factor::query()->whereKey($start->factor?->id)->sole());
    }

    /**
     * Run the callback with the package's tables reached through the observer.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    private function asObserver(\Closure $callback): mixed
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            return $callback();
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * Sign a person in, with a first factor and just proved again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signIn(): void
    {
        Mfa::extend('other', fn (): RecordingFactorDriver => new RecordingFactorDriver);

        $user  = TestUser::query()->create(['email' => 'race@example.test']);
        $store = $this->container()->make(ProofStore::class);

        $this->actingAs($user);

        $store->begin($user, 'web', 'race-sign-in');
        $store->record(SignInProofs::of($user)->inSession('race-sign-in')->password(60));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        CarbonImmutable::setTestNow(CarbonImmutable::now());
    }
}
