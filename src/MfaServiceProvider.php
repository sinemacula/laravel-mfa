<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Policies\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Stores\SessionMfaVerificationStore;

/**
 * MFA service provider.
 *
 * Bootstraps the multi-factor authentication services including
 * the MFA manager, configuration merging, and config publishing.
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
        $this->app->singleton('mfa', fn (Application $app) => new MfaManager($app));
    }

    /**
     * Register the default MFA policy binding.
     *
     * Consumers who need external enforcement (organisation-level,
     * role-level, feature-flag-level) rebind the `MfaPolicy`
     * contract to their own implementation in their own service
     * provider.
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
     * `MfaVerificationStore` contract in their own service
     * provider; `laravel-iam` ships a `DeviceMfaVerificationStore`
     * for paired-mode stateless operation.
     *
     * @return void
     */
    protected function registerMfaVerificationStore(): void
    {
        $this->app->singleton(MfaVerificationStore::class, static fn (Application $app): MfaVerificationStore => new SessionMfaVerificationStore($app->make(Session::class)));
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
