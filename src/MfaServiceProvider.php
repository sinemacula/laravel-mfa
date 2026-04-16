<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Gateways\NullSmsGateway;
use SineMacula\Laravel\Mfa\Policies\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Stores\SessionMfaVerificationStore;

/**
 * MFA service provider.
 *
 * Bootstraps the multi-factor authentication services: the MFA manager
 * singleton, the default policy / verification store / SMS gateway
 * bindings, mail view loading, and config / migration / view publishing.
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
    }

    /**
     * Register the MFA manager singleton.
     *
     * @return void
     */
    protected function registerMfaManager(): void
    {
        $this->app->singleton('mfa', static fn (Application $app) => new MfaManager($app));
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
