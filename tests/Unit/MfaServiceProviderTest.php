<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Config\Repository;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\NullSmsGateway;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use SineMacula\Laravel\Mfa\Http\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Http\Middleware\SkipMfa;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\SessionMfaVerificationStore;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\TestCase;

/**
 * Unit tests for the `MfaServiceProvider` container wiring.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaServiceProvider::class)]
final class MfaServiceProviderTest extends TestCase
{
    /**
     * Test binds mfa manager as singleton under mfa alias.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsMfaManagerAsSingletonUnderMfaAlias(): void
    {
        $first  = $this->container()->make('mfa');
        $second = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $first);
        self::assertSame($first, $second);
    }

    /**
     * Test binds mfa policy to null mfa policy.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsMfaPolicyToNullMfaPolicy(): void
    {
        self::assertInstanceOf(NullMfaPolicy::class, $this->container()->make(MfaPolicy::class));
    }

    /**
     * Test binds mfa verification store to session store.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsMfaVerificationStoreToSessionStore(): void
    {
        self::assertInstanceOf(
            SessionMfaVerificationStore::class,
            $this->container()->make(MfaVerificationStore::class),
        );
    }

    /**
     * Test binds sms gateway to null sms gateway.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsSmsGatewayToNullSmsGateway(): void
    {
        self::assertInstanceOf(NullSmsGateway::class, $this->container()->make(SmsGateway::class));
    }

    /**
     * Test registers each capability's services and defaults as singletons.
     *
     * @return void
     */
    public function testRegistersEachCapabilitysBindings(): void
    {
        $abstracts = [
            FactorService::class,
            FactorStateCache::class,
            DriverResolver::class,
            SmsGateway::class,
            MfaPolicy::class,
            RequirementService::class,
            MfaVerificationStore::class,
            ProofService::class,
            VerificationService::class,
            EnrollmentService::class,
            LifecycleService::class,
            RecoveryCodeService::class,
        ];

        foreach ($abstracts as $abstract) {
            self::assertTrue($this->container()->isShared($abstract), $abstract . ' is not registered as a singleton.');
        }
    }

    /**
     * Test registers the shipped drivers with the manager.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheShippedDrivers(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
        self::assertInstanceOf(TotpDriver::class, $manager->driver('totp'));
        self::assertInstanceOf(EmailDriver::class, $manager->driver('email'));
        self::assertInstanceOf(SmsDriver::class, $manager->driver('sms'));
        self::assertInstanceOf(BackupCodeDriver::class, $manager->driver('backup_code'));
    }

    /**
     * Test registers middleware aliases.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->container()->make(Router::class);

        $middleware = $router->getMiddleware();

        self::assertArrayHasKey('mfa', $middleware);
        self::assertArrayHasKey('mfa.skip', $middleware);
        self::assertSame(RequireMfa::class, $middleware['mfa']);
        self::assertSame(SkipMfa::class, $middleware['mfa.skip']);
    }

    /**
     * Test merges default mfa config.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMergesDefaultMfaConfig(): void
    {
        $config = $this->container()->make('config');

        // Sanity check: the config file shipped with the package has been
        // merged into the runtime configuration.
        self::assertIsArray($config->get('mfa'));
        self::assertSame('mfa_factors', $config->get('mfa.factor.table'));
    }

    /**
     * Test registers config publishing tag.
     *
     * @return void
     */
    public function testRegistersConfigPublishingTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            null,
            'mfa-config',
        );

        self::assertNotEmpty($paths);
        self::assertContains(config_path('mfa.php'), $paths);
    }

    /**
     * Test registers migration publishing tag.
     *
     * @return void
     */
    public function testRegistersMigrationPublishingTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            null,
            'mfa-migrations',
        );

        self::assertNotEmpty($paths);
    }

    /**
     * Test offer publishing is skipped when not running in console.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testOfferPublishingIsSkippedWhenNotRunningInConsole(): void
    {
        // Build a throwaway testbench kernel whose `runningInConsole()` returns
        // false so we exercise the early-return in `offerPublishing()`.
        $app = new class extends Application {
            /**
             * Running in console.
             *
             * @imperative
             *
             * @return bool
             */
            #[\Override]
            public function runningInConsole(): bool
            {
                return false;
            }
        };

        // The booted provider only consults the config to decide what to
        // publish, and `runningInConsole()` short-circuits that path for this
        // test — so an empty repository is sufficient and avoids loading the
        // real config file via `require` / `include` (both forbidden by the
        // project's lint rules outside namespace imports).
        $app->bind('config', static fn () => new Repository(['mfa' => []]));
        $app->bind(Router::class, static fn ($app) => new Router(
            new Dispatcher($app),
        ));

        // Snapshot the pre-boot publishable paths so we can assert the
        // short-circuit leaves them untouched. Using the shared static registry
        // means other tests may have pre-registered paths under the real
        // provider class; diffing before/after isolates this boot's
        // contribution.
        $providerClass = MfaServiceProvider::class;

        /** @var array<string, mixed> $before */
        $before = ServiceProvider::$publishes[$providerClass] ?? [];

        $provider = new MfaServiceProvider($app);

        $provider->boot();

        /** @var array<string, mixed> $after */
        $after = ServiceProvider::$publishes[$providerClass] ?? [];

        self::assertSame(
            $before,
            $after,
            'offerPublishing() must not register publishes under a non-console kernel',
        );
    }
}
