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
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\OtherConnectionUser;
use Tests\TestCase;

/**
 * An identity on another connection: Eloquent gives a related model its
 * parent's connection unless it names one, so the factor model names storage's.
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
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecoveryCodeGeneratedForTheIdentityRedeemsOnce(): void
    {
        $user = $this->loginUser();

        $user->factors()->create(['type' => 'totp', 'status' => 'confirmed']);

        $codes = $this->container()->make(RecoveryCodeService::class)->generate($user, 'web');

        self::assertCount(10, $codes);
        self::assertSame(StorageConnection::resolvedName(), (new RecoveryCode)->getConnectionName());
        self::assertSame(10, RecoveryCode::query()->where('authenticatable_id', (string) $user->id)->count());

        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($codes[0]->reveal()))->isVerified());
        self::assertTrue(Mfa::verify(Callers::current(), Submission::recoveryCode($codes[0]->reveal()))->isFailed());
        self::assertSame(9, Mfa::recoveryCodeStatus(Callers::current())?->remaining);
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
