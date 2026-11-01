<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Mfa\Codes\CodeBindings;
use SineMacula\Laravel\Mfa\Drivers\DriverBindings;
use SineMacula\Laravel\Mfa\Enrolment\EnrolmentBindings;
use SineMacula\Laravel\Mfa\Factors\FactorBindings;
use SineMacula\Laravel\Mfa\Http\HttpBindings;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeBindings;
use SineMacula\Laravel\Mfa\Requirements\RequirementBindings;
use SineMacula\Laravel\Mfa\Verification\VerificationBindings;

/**
 * MFA service provider.
 *
 * Registers the `mfa` manager singleton and the configuration, then hands each
 * capability's container wiring to that capability's `*Bindings` class: its
 * service, its defaults for the seams consumers rebind (policy, verification
 * store, SMS gateway) and the drivers it ships. Boots the middleware aliases
 * and config and migration publishing.
 *
 * Consumers with their own enforcement policy, stateless verification store, or
 * real SMS gateway rebind the matching contracts in their own service provider;
 * `laravel-iam` ships an opinionated set of bindings for paired-mode use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MfaServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/mfa.php', 'mfa');

        $this->app->singleton('mfa', static fn (Application $app): MfaManager => new MfaManager($app));

        FactorBindings::register($this->app);
        DriverBindings::register($this->app);
        CodeBindings::register($this->app);
        RequirementBindings::register($this->app);
        ProofBindings::register($this->app);
        VerificationBindings::register($this->app);
        EnrolmentBindings::register($this->app);
        LifecycleBindings::register($this->app);
        RecoveryCodeBindings::register($this->app);
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->offerPublishing();

        HttpBindings::boot($this->app);
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
