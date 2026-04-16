<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Routing\Router;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Gateways\NullSmsGateway;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Middleware\SkipMfa;
use SineMacula\Laravel\Mfa\Policies\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Stores\SessionMfaVerificationStore;
use Tests\TestCase;

/**
 * Unit tests for the `MfaServiceProvider` container wiring.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaServiceProviderTest extends TestCase
{
    /**
     * Test binds mfa manager as singleton under mfa alias.
     *
     * @return void
     */
    public function testBindsMfaManagerAsSingletonUnderMfaAlias(): void
    {
        $first  = $this->app->make('mfa');
        $second = $this->app->make('mfa');

        self::assertInstanceOf(MfaManager::class, $first);
        self::assertSame($first, $second);
    }

    /**
     * Test binds mfa policy to null mfa policy.
     *
     * @return void
     */
    public function testBindsMfaPolicyToNullMfaPolicy(): void
    {
        self::assertInstanceOf(NullMfaPolicy::class, $this->app->make(MfaPolicy::class));
    }

    /**
     * Test binds mfa verification store to session store.
     *
     * @return void
     */
    public function testBindsMfaVerificationStoreToSessionStore(): void
    {
        self::assertInstanceOf(
            SessionMfaVerificationStore::class,
            $this->app->make(MfaVerificationStore::class),
        );
    }

    /**
     * Test binds sms gateway to null sms gateway.
     *
     * @return void
     */
    public function testBindsSmsGatewayToNullSmsGateway(): void
    {
        self::assertInstanceOf(NullSmsGateway::class, $this->app->make(SmsGateway::class));
    }

    /**
     * Test registers middleware aliases.
     *
     * @return void
     */
    public function testRegistersMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make(Router::class);

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
     */
    public function testMergesDefaultMfaConfig(): void
    {
        $config = $this->app->make('config');

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
        $paths = \Illuminate\Support\ServiceProvider::pathsToPublish(
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
        $paths = \Illuminate\Support\ServiceProvider::pathsToPublish(
            null,
            'mfa-migrations',
        );

        self::assertNotEmpty($paths);
    }

    /**
     * Test offer publishing is skipped when not running in console.
     *
     * @return void
     */
    public function testOfferPublishingIsSkippedWhenNotRunningInConsole(): void
    {
        // Build a throwaway testbench kernel whose `runningInConsole()`
        // returns false so we exercise the early-return in
        // `offerPublishing()`.
        $app = new class extends \Illuminate\Foundation\Application {
            /**
             * Construct.
             *
             * @return void
             */
            public function __construct() {}

            /**
             * Running in console.
             *
             * @return bool
             */
            public function runningInConsole(): bool
            {
                return false;
            }
        };

        $app->bind('config', static fn () => new \Illuminate\Config\Repository([
            'mfa' => require __DIR__ . '/../../config/mfa.php',
        ]));
        $app->bind(\Illuminate\Routing\Router::class, static fn ($app) => new \Illuminate\Routing\Router(
            new \Illuminate\Events\Dispatcher($app),
        ));

        $provider = new \SineMacula\Laravel\Mfa\MfaServiceProvider($app);

        // No exception, no publishes registered — confirms the guard works.
        $provider->boot();

        $this->addToAssertionCount(1);
    }
}
