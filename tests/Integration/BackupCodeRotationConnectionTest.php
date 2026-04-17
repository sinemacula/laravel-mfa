<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\SecondaryConnectionFactor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Backup-code rotation must open its transaction on the factor model's own
 * connection, not the container-default `ConnectionInterface` binding.
 *
 * A consumer who points `config('mfa.factor.model')` at a subclass bound to a
 * non-default database connection relies on the documented atomic-replace
 * guarantee holding on THAT connection. If the manager opened the outer
 * transaction against the default connection, the rotation's delete-then-
 * insert work would run outside any transaction on the factor connection and
 * a failure mid-rotation would leave the identity with zero backup codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class BackupCodeRotationConnectionTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Rotation reads and writes on the factor model's connection, so rows
     * land on the secondary connection and the default connection is left
     * untouched.
     *
     * @return void
     */
    public function testRotationWritesToFactorModelConnection(): void
    {
        $this->prepareSecondaryConnection();

        $user = $this->loginUser();

        config()->set('mfa.factor.model', SecondaryConnectionFactor::class);

        $codes = Mfa::issueBackupCodes();

        self::assertCount(10, $codes);

        self::assertSame(
            10,
            self::countBackupCodes(
                SecondaryConnectionFactor::query(),
                (string) $user->id,
            ),
        );

        self::assertSame(
            0,
            self::countBackupCodes(
                Factor::query(),
                (string) $user->id,
            ),
            'Rotation must not touch the default connection when the factor model is bound elsewhere.',
        );
    }

    /**
     * A failure partway through the rotation must roll back every write on the
     * factor model's own connection — prior rows survive and the partial new
     * batch is discarded.
     *
     * @return void
     */
    public function testRotationRollsBackOnFactorModelConnectionWhenMidRotationFailureOccurs(): void
    {
        $this->prepareSecondaryConnection();

        $user = $this->loginUser();

        config()->set('mfa.factor.model', SecondaryConnectionFactor::class);

        // Seed a pre-existing backup-code row on the secondary connection.
        // It must still be there after the aborted rotation.
        $prior                       = new SecondaryConnectionFactor;
        $prior->authenticatable_type = $user->getMorphClass();
        $prior->authenticatable_id   = (string) $user->id;
        $prior->driver               = BackupCodeDriver::NAME;
        $prior->secret               = 'prior-hash';
        $prior->save();

        $priorId = $prior->id;

        // Force the rotation to fail after a few inserts so we can prove
        // the transaction rolls back in-flight writes on the factor
        // model's connection.
        /** @var \Illuminate\Events\Dispatcher $events */
        $events = $this->container()->make(Dispatcher::class);

        $seen = 0;
        $events->listen(MfaFactorEnrolled::class, static function () use (&$seen): void {
            $seen++;

            if ($seen === 3) {
                throw new MidRotationFailureException('mid-rotation failure');
            }
        });

        try {
            Mfa::issueBackupCodes();
            self::fail('Expected the mid-rotation listener to throw.');
        } catch (MidRotationFailureException $e) {
            self::assertSame('mid-rotation failure', $e->getMessage());
        }

        // Prior row must still exist and no partial batch should remain.
        $remaining = SecondaryConnectionFactor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('driver', BackupCodeDriver::NAME)
            ->pluck('id')
            ->all();

        self::assertSame(
            [$priorId],
            $remaining,
            'The transaction must roll back delete-and-insert work on the factor connection.',
        );
    }

    /**
     * Register a secondary in-memory SQLite connection so the test can bind a
     * custom factor model to a connection other than the default.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.secondary', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    /**
     * Authenticate as a fresh MFA-enabled `TestUser`.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function loginUser(): TestUser
    {
        $user = TestUser::query()->create([
            'email'       => 'rotation@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Count backup-code rows for the given identifier against the supplied
     * factor-model builder. Wraps the dynamic `count()` call so PHPStan does
     * not flag it as a dynamic call to a static method on the model.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Factor>  $builder
     * @param  string  $identifier
     * @return int
     *
     * @formatter:on
     */
    private static function countBackupCodes(Builder $builder, string $identifier): int
    {
        return $builder
            ->where('authenticatable_id', $identifier)
            ->where('driver', BackupCodeDriver::NAME)
            ->toBase()
            ->count();
    }

    /**
     * Create the `mfa_factors` table on the secondary connection so
     * `SecondaryConnectionFactor` has somewhere to write.
     *
     * @return void
     */
    private function prepareSecondaryConnection(): void
    {
        $schema = $this->container()->make('db')
            ->connection('secondary')
            ->getSchemaBuilder();

        $schema->create('mfa_factors', static function (Blueprint $blueprint): void {
            $blueprint->ulid('id')->primary();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id']);
            $blueprint->string('driver')->index();
            $blueprint->string('label')->nullable();
            $blueprint->string('recipient')->nullable();
            $blueprint->text('secret')->nullable();
            $blueprint->text('code')->nullable();
            $blueprint->timestamp('expires_at')->nullable();
            $blueprint->unsignedInteger('attempts')->default(0);
            $blueprint->timestamp('locked_until')->nullable();
            $blueprint->timestamp('last_attempted_at')->nullable();
            $blueprint->timestamp('verified_at')->nullable();
            $blueprint->timestamps();
        });
    }
}
