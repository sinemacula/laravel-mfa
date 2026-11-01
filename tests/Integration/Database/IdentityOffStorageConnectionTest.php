<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use Tests\Fixtures\Identities\OtherConnectionUser;
use Tests\TestCase;

/**
 * An identity on a connection other than the storage connection.
 *
 * With `mfa.storage.connection` left unset, the package's tables live on the
 * default connection while the identity lives on `identities`. Eloquent gives a
 * related model that names no connection its parent's, so the factor model
 * names the storage connection itself: the identity's factors are read and
 * written on the default connection, and a backup code issued for it verifies
 * once, in a factor state transaction the storage connection accepts.
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
     * A backup code issued for the identity is stored on the storage connection
     * and verifies exactly once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABackupCodeIssuedForTheIdentityVerifiesOnce(): void
    {
        $user  = $this->loginUser();
        $codes = Mfa::issueBackupCodes();

        self::assertCount(10, $codes);
        self::assertSame(10, $user->authFactors()->count());

        $factor = $this->factorFor($user, $codes[0]);

        self::assertTrue(Mfa::verify(BackupCodeDriver::NAME, $factor, $codes[0]));

        $factor->refresh();

        self::assertFalse(Mfa::verify(BackupCodeDriver::NAME, $factor, $codes[0]));
        self::assertSame(9, $user->authFactors()->whereNotNull('secret')->count());
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
    }

    /**
     * Authenticate as a fresh MFA-enabled identity on the identities
     * connection.
     *
     * @return \Tests\Fixtures\Identities\OtherConnectionUser
     */
    private function loginUser(): OtherConnectionUser
    {
        $user = OtherConnectionUser::query()->create([
            'email'       => 'elsewhere@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * The identity's backup-code factor that holds the given code.
     *
     * @param  \Tests\Fixtures\Identities\OtherConnectionUser  $user
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorFor(OtherConnectionUser $user, string $code): Factor
    {
        $hash = (new BackupCodeDriver)->hash($code);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return $user->factors()->get()->firstOrFail(static fn (Factor $factor): bool => $factor->getSecret() === $hash);
    }
}
