<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * Events follow the transaction on the `secondary` storage connection, not one
 * on the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterStorageCommit::class)]
#[CoversClass(EventDispatcher::class)]
final class StorageConnectionEventsTest extends TestCase
{
    use MigratesTheStorageConnection;

    /** @var list<string> Names of the events dispatched, oldest first. */
    private array $reported = [];

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->reported[] = class_basename($event);
        });
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testEventsWaitForTheStorageConnectionsCommit(): void
    {
        $user = $this->personWithAFactor();

        DB::connection('secondary')->transaction(function () use ($user): void {

            Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.');

            self::assertSame([], $this->reported);
        });

        self::assertSame(['FactorRemoved', 'FactorsReset'], $this->reported);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackOnTheStorageConnectionDispatchesNothing(): void
    {
        $user = $this->personWithAFactor();

        DB::connection('secondary')->beginTransaction();

        Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.');

        DB::connection('secondary')->rollBack();
        DB::connection('secondary')->transaction(static fn (): null => null);

        self::assertSame([], $this->reported);
        self::assertSame(1, Factor::query()->count());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnTheDefaultConnectionHoldsNothingBack(): void
    {
        $user = $this->personWithAFactor();

        DB::connection('testing')->beginTransaction();

        Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost phone.');

        self::assertSame(['FactorRemoved', 'FactorsReset'], $this->reported);

        DB::connection('testing')->rollBack();

        self::assertSame(['FactorRemoved', 'FactorsReset'], $this->reported);
        self::assertSame(0, Factor::query()->count());
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
    }

    /**
     * Stored outside any transaction the test opens.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function personWithAFactor(): TestUser
    {
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        return $user;
    }
}
