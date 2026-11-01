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
 * Registers the configuration and the `mfa` manager singleton, then hands each
 * capability's container wiring to that capability's `*Bindings` class: its
 * service and its defaults for the seams consumers rebind (policy, verification
 * store, SMS gateway). The shipped drivers are registered against the manager
 * by their capability's `*Bindings` class from inside the singleton's factory.
 * Boots the middleware aliases and config and migration publishing.
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

        $this->registerManager();

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
     * Register the MFA manager singleton with the shipped drivers.
     *
     * The shipped drivers are registered inside the factory, through the same
     * `extend()` API a consumer uses, so they exist before the container runs
     * any extender or resolving callback a consumer has attached to `mfa`. A
     * consumer's own registration of a shipped driver's name, whether made
     * there or later through `Mfa::extend()`, therefore always wins.
     *
     * @return void
     */
    protected function registerManager(): void
    {
        $this->app->singleton('mfa', static function (Application $app): MfaManager {
            $manager = new MfaManager($app);

            DriverBindings::extend($manager, $app);
            RecoveryCodeBindings::extend($manager, $app);

            return $manager;
        });
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
