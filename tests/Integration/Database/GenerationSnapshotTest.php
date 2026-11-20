<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * A generation advance `observer` commits after the application's transaction
 * took its snapshot still binds a decision made under the identity's lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationGeneration::class)]
#[CoversClass(FactorStateTransaction::class)]
final class GenerationSnapshotTest extends TestCase
{
    /**
     * Ends a transaction a failed test left open before migrations roll back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A plain read misses the advance; the enrolment's liveness does not. The
     * frozen clock leaves the lock's `updated_at` unchanged, as within one
     * second, so the locked row keeps the snapshot's version.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOlderMysqlSnapshotCannotHideAnAdvanceFromAnEnrollment(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('This behaviour belongs to mysql.');
        }

        $user  = $this->signIn();
        $start = Mfa::startEnrollment(Callers::current(), EnrollmentRequest::totp('person@example.test'));
        $code  = AuthenticatorApp::code(Factor::query()->whereKey($start->factor?->id)->sole());

        DB::connection()->unprepared('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        DB::connection()->beginTransaction();

        self::assertSame(0, VerificationGeneration::current($user));

        config()->set('mfa.storage.connection', 'observer');

        try {
            self::assertSame(1, VerificationGeneration::advance($user));
        } finally {
            config()->set('mfa.storage.connection', null);
        }

        self::assertSame(0, VerificationGeneration::current($user));

        $confirmation = Mfa::confirmEnrollment(Callers::current(), (string) $start->grant?->reveal(), $code);

        DB::connection()->commit();

        self::assertSame(FailureReason::EXPIRED, $confirmation->reason);
        self::assertSame(0, Factor::query()->where('status', 'confirmed')->count());
    }

    /**
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.observer', $config->get('database.connections.testing'));
        $config->set('mfa.applications.web', [
            'types'        => ['totp'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signIn(): TestUser
    {
        $user  = TestUser::query()->create(['email' => 'snapshot@example.test']);
        $store = $this->container()->make(ProofStore::class);

        $this->actingAs($user);

        $store->begin($user, 'web', 'snapshot-sign-in');
        $store->record($user, SignInProofs::of($user)->inSession('snapshot-sign-in')->password(60));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        CarbonImmutable::setTestNow(CarbonImmutable::now());

        return $user;
    }
}
