<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Mfa\Assurance\AssuranceBindings;
use SineMacula\Laravel\Mfa\Codes\CodeBindings;
use SineMacula\Laravel\Mfa\Config\ConfigurationBindings;
use SineMacula\Laravel\Mfa\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Mfa\Console\PruneCommand;
use SineMacula\Laravel\Mfa\Context\ContextBindings;
use SineMacula\Laravel\Mfa\Drivers\DriverBindings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentBindings;
use SineMacula\Laravel\Mfa\Events\EventBindings;
use SineMacula\Laravel\Mfa\Factors\FactorBindings;
use SineMacula\Laravel\Mfa\Http\HttpBindings;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleBindings;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeBindings;
use SineMacula\Laravel\Mfa\Requirements\RequirementBindings;
use SineMacula\Laravel\Mfa\Seams\SeamBindings;
use SineMacula\Laravel\Mfa\Secrets\SecretBindings;
use SineMacula\Laravel\Mfa\Verification\VerificationBindings;

/**
 * Registers the `mfa` manager and hands each capability's wiring to its
 * `*Bindings` class. Only `mfa` is shared, for long-running processes.
 *
 * Every default is bound only when nothing is bound yet, so a consumer's
 * binding wins whether made before or after this provider registers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MfaServiceProvider extends ServiceProvider
{
    /**
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/mfa.php', 'mfa');

        $this->registerManager();

        EventBindings::register($this->app);
        ContextBindings::register($this->app);
        SeamBindings::register($this->app);
        FactorBindings::register($this->app);
        DriverBindings::register($this->app);
        CodeBindings::register($this->app);
        AssuranceBindings::register($this->app);
        RequirementBindings::register($this->app);
        ProofBindings::register($this->app);
        VerificationBindings::register($this->app);
        EnrollmentBindings::register($this->app);
        LifecycleBindings::register($this->app);
        RecoveryCodeBindings::register($this->app);
        PasskeyBindings::register($this->app);
        HttpBindings::register($this->app);
    }

    /**
     * @return void
     */
    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'mfa');

        $this->offerPublishing();
        $this->registerCommands();

        HttpBindings::boot($this->app);
        SecretBindings::boot($this->app);
        ConfigurationBindings::boot($this->app);
    }

    /**
     * The shipped drivers are registered inside the factory, before any
     * consumer extender runs, so a consumer's registration always wins.
     *
     * @return void
     */
    protected function registerManager(): void
    {
        $this->app->singletonIf('mfa', static function (Application $app): MfaManager {

            ConfigurationBindings::validate($app);

            $manager = new MfaManager($app);

            DriverBindings::extend($manager);

            return $manager;
        });
    }

    /**
     * @return void
     */
    protected function registerCommands(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->commands([CheckConfigurationCommand::class, PruneCommand::class]);
    }

    /**
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

        $this->publishes([
            __DIR__ . '/../lang' => $this->app->langPath('vendor/mfa'),
        ], 'mfa-lang');
    }
}
