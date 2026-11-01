<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\TestUser;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * The identity's factors, whether it has a confirmed one, and its re-enrolment
 * obligation are read from the write connection when the storage connection
 * splits its reads and writes.
 *
 * The storage connection reads from one SQLite file and writes to another,
 * standing in for a replica that has not yet caught up with the primary: both
 * hold the package's tables, but a factor written since is only on the writer.
 * A plain read through the connection misses it; the package's read finds it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversTrait(HasFactors::class)]
final class WriteConnectionReadTest extends TestCase
{
    use MigratesTheStorageConnection;

    /** @var string The SQLite file reads are served from. */
    private string $reader = '';

    /** @var string The SQLite file writes go to. */
    private string $writer = '';

    /**
     * Create the package's tables on the writer, then copy them to the reader
     * before anything is written, as a replica would hold them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();

        copy($this->writer, $this->reader);
    }

    /**
     * Remove both SQLite files once the application is gone.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        foreach ([$this->reader, $this->writer] as $file) {
            if ($file === '' || !is_file($file)) {
                continue;
            }

            unlink($file);
        }
    }

    /**
     * A factor on the writer and not yet on the reader is still among the
     * identity's factors.
     *
     * @return void
     */
    public function testAFactorNotYetOnTheReaderIsStillRead(): void
    {
        $user = TestUser::query()->create(['email' => 'lagging@example.test', 'mfa_enabled' => true]);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
        ]);

        self::assertSame(0, $user->authFactors()->count());

        $factors = Mfa::getFactors();

        self::assertNotNull($factors);
        self::assertSame([$factor->getKey()], $factors->map(static fn (Factor $read): mixed => $read->getKey())->all());
    }

    /**
     * A factor confirmed on the writer and not yet on the reader enables MFA
     * for an identity using the shipped trait, and the setup state agrees.
     *
     * @return void
     */
    public function testAConfirmedFactorNotYetOnTheReaderEnablesMfa(): void
    {
        $holder = FactorHolder::query()->create(['email' => 'confirmed@example.test']);

        $this->actingAs($holder);

        Factor::query()->create([
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        self::assertTrue($holder->isMfaEnabled());
        self::assertTrue(Mfa::isSetup());
    }

    /**
     * A factor removed on the writer and still on the reader no longer enables
     * MFA, and the setup state agrees.
     *
     * @return void
     */
    public function testAFactorRemovedButStillOnTheReaderNoLongerEnablesMfa(): void
    {
        $holder = FactorHolder::query()->create(['email' => 'removed@example.test']);

        $this->actingAs($holder);

        $now = CarbonImmutable::now();

        DB::connection('replica')->table('mfa_factors')->insert([
            'id'                   => Str::lower((string) Str::ulid()),
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
            'created_at'           => $now,
            'updated_at'           => $now,
        ]);

        self::assertFalse($holder->isMfaEnabled());
        self::assertFalse(Mfa::isSetup());
    }

    /**
     * A re-enrolment obligation set on the writer and not yet on the reader
     * still obliges the identity, so its sign-in still requires an additional
     * verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnObligationNotYetOnTheReaderStillObliges(): void
    {
        $holder = FactorHolder::query()->create(['email' => 'obliged@example.test']);
        $now    = CarbonImmutable::now();

        DB::connection('split')->table('mfa_identity_states')->insert([
            'id'                    => Str::lower((string) Str::ulid()),
            'authenticatable_type'  => $holder->getMorphClass(),
            'authenticatable_id'    => (string) $holder->id,
            'reenrollment_required' => true,
            'created_at'            => $now,
            'updated_at'            => $now,
        ]);

        $this->actingAs($holder);

        self::assertSame(0, DB::connection('replica')->table('mfa_identity_states')->count());
        self::assertTrue(ReenrollmentObligation::isRequired($holder));
        self::assertFalse(Mfa::requirement()->isEmpty());
    }

    /**
     * Put the package's tables on a connection that reads from one SQLite file
     * and writes to another.
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

        $prefix = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mfa-split-' . Str::lower((string) Str::ulid());

        $this->reader = $prefix . '-read.sqlite';
        $this->writer = $prefix . '-write.sqlite';

        touch($this->reader);
        touch($this->writer);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.split', [
            'driver' => 'sqlite',
            'read'   => ['database' => $this->reader],
            'write'  => ['database' => $this->writer],
            'sticky' => false,
            'prefix' => '',
        ]);

        $config->set('database.connections.replica', [
            'driver'   => 'sqlite',
            'database' => $this->reader,
            'prefix'   => '',
        ]);

        $config->set('mfa.storage.connection', 'split');
    }
}
