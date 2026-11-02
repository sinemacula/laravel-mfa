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
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
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
 * Each piece of state a verification depends on has a case here: the replica
 * catches up, the state changes on the writer, the replica is shown to be
 * behind, and the answer is the writer's: a replay refused, a lockout met, a
 * proof that no longer counts.
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

        $this->arrangeVerification();
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

        self::assertSame([$factor->getKey()], array_map(static fn (FactorSummary $read): string => $read->id, Mfa::factors()));
    }

    /**
     * A factor on the writer and not yet on the reader binds to a route.
     *
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
     * A factor confirmed on the writer and not yet on the reader enables MFA
     * for an identity using the shipped trait, and the listing agrees.
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
        self::assertCount(1, Mfa::factors());
    }

    /**
     * A factor removed on the writer and still on the reader no longer enables
     * MFA, and the listing agrees.
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
        self::assertSame([], Mfa::factors());
    }

    /**
     * A re-enrolment obligation set on the writer and not yet on the reader
     * still obliges the identity, so its sign-in still requires an additional
     * verification.
     *
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
        self::assertFalse(Mfa::requirement()->isEmpty());
    }

    /**
     * A time step accepted on the writer and not yet on the reader is still a
     * replay.
     *
     * @return void
     */
    public function testAnAcceptedStepNotYetOnTheReaderStillRefusesTheReplay(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        self::assertTrue(Mfa::verify(Submission::factor($factor->id, $code))->isVerified());
        self::assertNull(DB::connection('replica')->table('mfa_factors')->where('id', $factor->id)->value('last_accepted_step'));

        self::assertSame(FailureReason::REPLAYED, Mfa::verify(Submission::factor($factor->id, $code))->reason);
    }

    /**
     * A factor's lockout on the writer and not yet on the reader still holds.
     *
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

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * An identity's lockout on the writer and not yet on the reader still
     * holds.
     *
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

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * Failures counted on the writer and not yet on the reader still add up, so
     * the last one locks the factor.
     *
     * @return void
     */
    public function testAnAttemptCountNotYetOnTheReaderStillAddsUp(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->recordFirstFactor($user);
        $this->replicaCatchesUp();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse(Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor, 5)))->isVerified());
        }

        self::assertSame(0, DB::connection('replica')->table('mfa_attempts')->count());

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * A code consumed on the writer and not yet on the reader cannot be spent
     * again.
     *
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

        self::assertTrue(Mfa::verify($submission)->isVerified());
        self::assertNull(DB::connection('replica')->table('mfa_codes')->value('consumed_at'));

        self::assertFalse(Mfa::verify($submission)->isVerified());
    }

    /**
     * A recovery code used on the writer and not yet on the reader cannot be
     * used again.
     *
     * @return void
     */
    public function testARecoveryCodeUsedOnTheWriterCannotBeUsedAgain(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);
        $this->recordFirstFactor($user);

        $code = $this->recoveryCode($user);

        $this->replicaCatchesUp();

        self::assertTrue(Mfa::verify(Submission::recoveryCode($code))->isVerified());
        self::assertSame(0, DB::connection('replica')->table('mfa_recovery_codes')->whereNotNull('used_at')->count());

        self::assertFalse(Mfa::verify(Submission::recoveryCode($code))->isVerified());
    }

    /**
     * A factor removed on the writer and still on the reader verifies nothing.
     *
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

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
    }

    /**
     * A generation advanced on the writer and not yet on the reader stops the
     * proofs of the earlier one counting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGenerationNotYetOnTheReaderStillStopsOlderProofs(): void
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        self::assertCount(1, Mfa::proofs());

        $this->replicaCatchesUp();

        VerificationGeneration::advance($user);

        self::assertSame(0, DB::connection('replica')->table('mfa_identity_states')->count());
        self::assertSame(1, VerificationGeneration::current($user));
        self::assertSame([], Mfa::proofs());
    }

    /**
     * A credential associated on the writer and not yet on the reader is
     * associated.
     *
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

    /**
     * Bring the replica up to the writer, as it stood a moment ago.
     *
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
