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
 * MFA service provider.
 *
 * Registers the configuration and the `mfa` manager singleton, then hands each
 * capability's container wiring to that capability's `*Bindings` class: its
 * service and its fail-closed defaults for the seams consumers rebind
 * (requirements, proof store, pending sessions, subject type, first factor,
 * reauthentication, session revocation and transition, challenges, passkeys,
 * the last factor, SMS and email senders, event context). The shipped drivers
 * are registered against the manager by their capability's `*Bindings` class
 * from inside the singleton's factory, once the configuration is checked. Boots
 * the translations, the middleware aliases, config, migration and translation
 * publishing, the `mfa:check` command, and the configuration check that runs
 * once the application has booted, which also refuses a factor model off the
 * storage connection.
 *
 * Only `mfa` is shared: every service and default is built when it is asked
 * for, on the application serving at the time (see the long-running processes
 * design note).
 *
 * Consumers with their own requirement policy, stateless proof store, or SMS
 * and email senders rebind the matching contracts in their own service
 * provider; `laravel-iam` ships an opinionated set of bindings for paired-mode
 * use. Every default, and `mfa` itself, is bound only when nothing is bound
 * yet, so a binding made before this provider registers is kept, and one made
 * after replaces the default.
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
     * Bootstrap any application services.
     *
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
     * Register the MFA manager singleton with the shipped drivers, checking the
     * configuration before building it, unless `mfa` is already bound.
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
        $this->app->singletonIf('mfa', static function (Application $app): MfaManager {

            ConfigurationBindings::validate($app);

            $manager = new MfaManager($app);

            DriverBindings::extend($manager);

            return $manager;
        });
    }

    /**
     * Register the package's console commands when running in the console.
     *
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
     * Offer config, migration and translation publishing.
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

        $this->publishes([
            __DIR__ . '/../lang' => $this->app->langPath('vendor/mfa'),
        ], 'mfa-lang');
    }
}
