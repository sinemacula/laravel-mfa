<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use Tests\Fixtures\Identities\OtherConnectionUser;
use Tests\TestCase;

/**
 * An identity on a connection other than the storage connection.
 *
 * With `mfa.storage.connection` left unset, the package's tables live on the
 * default connection while the identity lives on `identities`. Eloquent gives a
 * related model that names no connection its parent's, so the factor model
 * names the storage connection itself: the identity's factors are read and
 * written on the default connection, and a recovery code generated for it
 * redeems once, in a factor state transaction the storage connection accepts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Factor::class)]
final class IdentityOffStorageConnectionTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Create the identity's table on its own connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::connection('identities')->create('test_users', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->nullable();
            $blueprint->boolean('mfa_enabled')->default(false);
            $blueprint->string('password')->nullable();
            $blueprint->string('remember_token', 100)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * The identity's factor relation reads the factors on the storage
     * connection, not on the identity's own.
     *
     * @return void
     */
    public function testTheIdentitysFactorsLiveOnTheStorageConnection(): void
    {
        $user = $this->loginUser();

        self::assertSame('identities', $user->getConnectionName());
        self::assertSame(StorageConnection::resolvedName(), $user->authFactors()->getModel()->getConnectionName());
        self::assertSame(StorageConnection::resolvedName(), $user->factors()->getRelated()->getConnectionName());
    }

    /**
     * A recovery code generated for the identity is stored on the storage
     * connection and redeems exactly once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecoveryCodeGeneratedForTheIdentityRedeemsOnce(): void
    {
        $user = $this->loginUser();

        $user->factors()->create(['type' => 'totp', 'status' => 'confirmed']);

        $codes = Mfa::generateRecoveryCodes();

        self::assertCount(10, $codes);
        self::assertSame(StorageConnection::resolvedName(), (new RecoveryCode)->getConnectionName());
        self::assertSame(10, RecoveryCode::query()->where('authenticatable_id', (string) $user->id)->count());

        self::assertTrue(Mfa::redeemRecoveryCode($codes[0]->reveal()));
        self::assertFalse(Mfa::redeemRecoveryCode($codes[0]->reveal()));
        self::assertSame(9, Mfa::recoveryCodes()?->remaining);
    }

    /**
     * Add the identities connection, leaving the storage connection unset.
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

        $config->set('database.connections.identities', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('mfa.storage.connection', null);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.applications.web', [
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * Sign in as a fresh MFA-enabled identity on the identities connection.
     *
     * @return \Tests\Fixtures\Identities\OtherConnectionUser
     */
    private function loginUser(): OtherConnectionUser
    {
        $user = OtherConnectionUser::query()->create([
            'email'       => 'elsewhere@example.test',
            'mfa_enabled' => true,
        ]);

        Auth::login($user);

        return $user;
    }
}
