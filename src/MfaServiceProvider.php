<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Contracts\Session\Session;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Gateways\NullSmsGateway;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Middleware\SkipMfa;
use SineMacula\Laravel\Mfa\Policies\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Stores\SessionMfaVerificationStore;

/**
 * MFA service provider.
 *
 * Bootstraps the multi-factor authentication services: the MFA manager
 * singleton, the default policy / verification store / SMS gateway
 * bindings, the middleware aliases, and config + migration publishing.
 *
 * Consumers with their own enforcement policy, stateless verification
 * store, or real SMS gateway rebind the matching contracts in their
 * own service provider; `laravel-iam` ships an opinionated set of
 * bindings for paired-mode use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/mfa.php', 'mfa');

        $this->registerMfaPolicy();
        $this->registerMfaVerificationStore();
        $this->registerSmsGateway();
        $this->registerMfaManager();
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->offerPublishing();
        $this->registerMiddlewareAliases();
    }

    /**
     * Register the MFA manager singleton.
     *
     * Built-in driver factories (TOTP, email, SMS, backup codes) are
     * registered against the manager via the standard `extend()` API at
     * construction time. Consumers can override any of them by calling
     * `Mfa::extend('totp', ...)` from their own service provider after
     * the package's provider has booted.
     *
     * @return void
     */
    protected function registerMfaManager(): void
    {
        // `static::` rather than `self::` so subclasses overriding
        // `registerBuiltInDrivers()` are honoured even when the closure
        // is invoked at resolve time.
        $this->app->singleton('mfa', static function (Application $app): MfaManager {
            $manager = new MfaManager($app);

            static::registerBuiltInDrivers($manager, $app);

            return $manager;
        });
    }

    /**
     * Register the four shipped factor drivers against the given
     * manager, threading per-driver configuration through each
     * factory closure.
     *
     * @param  \SineMacula\Laravel\Mfa\MfaManager  $manager
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected static function registerBuiltInDrivers(MfaManager $manager, Application $app): void
    {
        $config = $app->make(Repository::class);

        $manager->extend('totp', function () use ($config): TotpDriver {
            /** @var array{window?: int} $cfg */
            $cfg = $config->get('mfa.drivers.totp', []);

            return new TotpDriver(window: $cfg['window'] ?? 1);
        });

        $manager->extend('email', function () use ($app, $config): EmailDriver {
            /**
             * @var array{
             *     code_length?: int,
             *     expiry?: int,
             *     max_attempts?: int,
             *     alphabet?: ?string,
             *     mailable?: class-string<\SineMacula\Laravel\Mfa\Mail\MfaCodeMessage>
             * } $cfg
             */
            $cfg = $config->get('mfa.drivers.email', []);

            return new EmailDriver(
                mailer: $app->make(Mailer::class),
                mailable: $cfg['mailable']        ?? MfaCodeMessage::class,
                codeLength: $cfg['code_length']   ?? 6,
                expiry: $cfg['expiry']            ?? 10,
                maxAttempts: $cfg['max_attempts'] ?? 3,
                alphabet: $cfg['alphabet']        ?? null,
            );
        });

        $manager->extend('sms', function () use ($app, $config): SmsDriver {
            /**
             * @var array{
             *     code_length?: int,
             *     expiry?: int,
             *     max_attempts?: int,
             *     alphabet?: ?string,
             *     message_template?: string
             * } $cfg
             */
            $cfg = $config->get('mfa.drivers.sms', []);

            return new SmsDriver(
                gateway: $app->make(SmsGateway::class),
                messageTemplate: $cfg['message_template']
                                                  ?? 'Your verification code is: :code',
                codeLength: $cfg['code_length']   ?? 6,
                expiry: $cfg['expiry']            ?? 10,
                maxAttempts: $cfg['max_attempts'] ?? 3,
                alphabet: $cfg['alphabet']        ?? null,
            );
        });

        $manager->extend('backup_code', function () use ($config): BackupCodeDriver {
            /**
             * @var array{
             *     code_length?: int,
             *     alphabet?: string,
             *     code_count?: int
             * } $cfg
             */
            $cfg = $config->get('mfa.drivers.backup_code', []);

            return new BackupCodeDriver(
                codeLength: $cfg['code_length'] ?? 10,
                alphabet: $cfg['alphabet']
                                                ?? '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',
                codeCount: $cfg['code_count']   ?? 10,
            );
        });
    }

    /**
     * Register the default MFA policy binding.
     *
     * Consumers who need external enforcement (organisation-level,
     * role-level, feature-flag-level) rebind the `MfaPolicy` contract
     * in their own service provider.
     *
     * @return void
     */
    protected function registerMfaPolicy(): void
    {
        $this->app->singleton(MfaPolicy::class, NullMfaPolicy::class);
    }

    /**
     * Register the default MFA verification store binding.
     *
     * Defaults to the session-backed store. Consumers running a
     * stateless stack (JWT, personal access tokens) rebind the
     * `MfaVerificationStore` contract in their own service provider;
     * `laravel-iam` ships a `DeviceMfaVerificationStore` for paired-
     * mode stateless operation.
     *
     * @return void
     */
    protected function registerMfaVerificationStore(): void
    {
        $this->app->singleton(
            MfaVerificationStore::class,
            static fn (Application $app): MfaVerificationStore => new SessionMfaVerificationStore(
                $app->make(Session::class),
            ),
        );
    }

    /**
     * Register the default SMS gateway binding.
     *
     * The shipped default fails loud on first use; consumers who enable
     * the SMS driver rebind the `SmsGateway` contract to an
     * implementation that talks to their chosen SMS provider.
     *
     * @return void
     */
    protected function registerSmsGateway(): void
    {
        $this->app->singleton(SmsGateway::class, NullSmsGateway::class);
    }

    /**
     * Register the package's middleware under short aliases so
     * consumers can reference them as `'mfa'` / `'mfa.skip'` in their
     * route files without importing FQCNs.
     *
     * @return void
     */
    protected function registerMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('mfa', RequireMfa::class);
        $router->aliasMiddleware('mfa.skip', SkipMfa::class);
    }

    /**
     * Offer config and migration publishing.
     *
     * @return void
     */
    protected function offerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/mfa.php' => config_path('mfa.php'),
        ], 'mfa-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/' => $this->app->databasePath('migrations'),
        ], 'mfa-migrations');
    }
}
