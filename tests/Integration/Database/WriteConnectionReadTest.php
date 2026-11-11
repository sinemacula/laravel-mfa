<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * State a verification depends on is read from the writer: the storage
 * connection reads one SQLite file and writes another, as a lagging replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(AttemptService::class)]
#[CoversClass(AttemptStore::class)]
#[CoversClass(PasskeyAssociations::class)]
#[CoversClass(VerificationGeneration::class)]
#[CoversTrait(HasFactors::class)]
#[CoversTrait(ResolvesFactorRouteBinding::class)]
final class WriteConnectionReadTest extends TestCase
{
    use ArrangesVerification, MigratesTheStorageConnection;

    /** @var string SQLite file reads are served from. */
    private string $reader = '';

    /** @var string SQLite file writes go to. */
    private string $writer = '';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();

        copy($this->writer, $this->reader);

        $this->arrangeVerification();
    }

    /**
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

        self::assertSame([$factor->getKey()], array_map(static fn (FactorSummary $read): string => $read->id, Mfa::factors(Callers::current())));
    }

    /**
     * @return void
     */
    public function testAFactorNotYetOnTheReaderStillBinds(): void
    {
        $user = TestUser::query()->create(['email' => 'bound@example.test', 'mfa_enabled' => true]);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
        ]);

        self::assertSame(0, Factor::query()->whereKey($factor->getKey())->count());
        self::assertSame($factor->getKey(), (new Factor)->resolveRouteBinding($factor->getKey())?->getKey());
        self::assertSame(0, Factor::query()->whereKey($factor->getKey())->count(), 'The connection must read the replica again afterwards.');
    }

    /**
     * Through the shipped `HasFactors` trait.
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
        self::assertCount(1, Mfa::factors(Callers::current()));
    }

    /**
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
        self::assertSame([], Mfa::factors(Callers::current()));
    }

    /**
     * @return void
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
        self::assertFalse(Mfa::requirement(Callers::current())->isEmpty());
    }

    /**
     * @return void
     */
    public function testAnAcceptedStepNotYetOnTheReaderStillRefusesTheReplay(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isVerified());
        self::assertNull(DB::connection('replica')->table('mfa_factors')->where('id', $factor->id)->value('last_accepted_step'));

        self::assertSame(FailureReason::REPLAYED, Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->reason);
    }

    /**
     * @return void
     */
    public function testAFactorLockoutNotYetOnTheReaderStillHolds(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        DB::connection('split')->table('mfa_factors')->where('id', $factor->id)->update(['locked_until' => CarbonImmutable::now()->addHour()]);

        self::assertNull(DB::connection('replica')->table('mfa_factors')->where('id', $factor->id)->value('locked_until'));

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * @return void
     */
    public function testAnIdentityLockoutNotYetOnTheReaderStillHolds(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        DB::connection('split')->table('mfa_identity_states')->insert([
            'id'                   => Str::lower((string) Str::ulid()),
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'locked_until'         => CarbonImmutable::now()->addHour(),
            'created_at'           => CarbonImmutable::now(),
            'updated_at'           => CarbonImmutable::now(),
        ]);

        self::assertSame(0, DB::connection('replica')->table('mfa_identity_states')->count());

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * @return void
     */
    public function testAnAttemptCountNotYetOnTheReaderStillAddsUp(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, 5)))->isVerified());
        }

        self::assertSame(0, DB::connection('replica')->table('mfa_attempts')->count());

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * @return void
     */
    public function testACodeConsumedOnTheWriterCannotBeSpentAgain(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user, attributes: ['application' => self::APPLICATION]);

        $this->recordFirstFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->replicaCatchesUp();

        $submission = Submission::challenge($factor->id, $challenge, $code);

        self::assertTrue(Mfa::verify(Callers::current(), $submission)->isVerified());
        self::assertNull(DB::connection('replica')->table('mfa_codes')->value('consumed_at'));

        self::assertFalse(Mfa::verify(Callers::current(), $submission)->isVerified());
    }

    /**
     * @return void
     */
    public function testARecoveryCodeUsedOnTheWriterCannotBeUsedAgain(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);
        $this->recordFirstFactor($user);

        $code = $this->recoveryCode($user);

        $this->replicaCatchesUp();

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($code))->isVerified());
        self::assertSame(0, DB::connection('replica')->table('mfa_recovery_codes')->whereNotNull('used_at')->count());

        self::assertFalse(Mfa::verify(Callers::current(), Submission::recoveryCode($code))->isVerified());
    }

    /**
     * @return void
     */
    public function testAFactorRemovedOnTheWriterVerifiesNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        DB::connection('split')->table('mfa_factors')->where('id', $factor->id)->delete();

        self::assertSame(1, DB::connection('replica')->table('mfa_factors')->count());

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGenerationNotYetOnTheReaderStillStopsOlderProofs(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        self::assertCount(1, Mfa::proofs(Callers::current()));

        $this->replicaCatchesUp();

        VerificationGeneration::advance($user);

        self::assertSame(0, DB::connection('replica')->table('mfa_identity_states')->count());
        self::assertSame(1, VerificationGeneration::current($user));
        self::assertSame([], Mfa::proofs(Callers::current()));
    }

    /**
     * @return void
     */
    public function testAnAssociationNotYetOnTheReaderIsStillFound(): void
    {
        $user = $this->signedInPerson();

        $this->replicaCatchesUp();

        $factor = $this->passkeyFactor($user);

        self::assertSame(0, DB::connection('replica')->table('mfa_passkey_associations')->count());

        $associations = $this->container()->make(PasskeyAssociations::class);

        self::assertTrue($associations->exists(self::CREDENTIAL));
        self::assertTrue($associations->associates($factor, ProofOwner::of($user)));
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

    /**
     * @return void
     */
    private function replicaCatchesUp(): void
    {
        foreach (['split', 'replica'] as $name) {
            $connection = DB::connection($name);

            self::assertInstanceOf(Connection::class, $connection);

            $connection->disconnect();
        }

        copy($this->writer, $this->reader);
    }
}
