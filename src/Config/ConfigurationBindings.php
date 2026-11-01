<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Console\CheckConfigurationCommand;

/**
 * Runs the configuration check once the application has booted, and from the
 * `mfa` manager's factory when it is resolved (see `ConfigurationValidator`),
 * so a misconfiguration fails before a person's first verification rather than
 * at it.
 *
 * The boot check waits until every service provider has booted, so a binding an
 * application makes in its own provider's `boot()` (an SMS gateway, a first
 * factor resolver) counts. It is skipped while `mfa:check` runs, which reports
 * the same problems instead of failing on them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigurationBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Check the configuration once the application has booted, unless
     * `mfa:check` is running.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function boot(Application $app): void
    {
        $app->booted(static function (Application $app): void {

            if (self::isRunningCheck($app)) {
                return;
            }

            self::validate($app);
        });
    }

    /**
     * Check the configuration now.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException
     */
    public static function validate(Application $app): void
    {
        $app->make(ConfigurationValidator::class)->validate();
    }

    /**
     * Whether the console command running is `mfa:check`.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isRunningCheck(Application $app): bool
    {
        return $app->runningInConsole() && ($_SERVER['argv'][1] ?? null) === CheckConfigurationCommand::NAME;
    }
}
