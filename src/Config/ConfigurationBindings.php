<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Console\CheckConfigurationCommand;
use Symfony\Component\Console\Input\ArgvInput;

/**
 * Runs the configuration check once the application has booted, and from the
 * `mfa` manager's factory when it is resolved (see `ConfigurationValidator`),
 * so a misconfiguration fails before a person's first verification rather than
 * at it.
 *
 * The boot check waits until every service provider has booted, so a binding an
 * application makes in its own provider's `boot()` (an SMS gateway, a first
 * factor resolver) counts. It is skipped while `mfa:check` runs, which reports
 * the same problems instead of failing on them, and while one of the console
 * commands that list, describe, discover, cache or clear configuration runs, so
 * a misconfiguration (a cached one included) can still be inspected and
 * cleared. Those commands never resolve the `mfa` manager, whose factory checks
 * the configuration whatever is running.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigurationBindings
{
    /** @var list<string> The console commands the boot check is skipped for. */
    private const array UNCHECKED_COMMANDS = [
        CheckConfigurationCommand::NAME,
        'config:cache',
        'config:clear',
        'config:show',
        'help',
        'list',
        'optimize:clear',
        'package:discover',
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Check the configuration once the application has booted, unless
     * `mfa:check` or a configuration maintenance command is running.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function boot(Application $app): void
    {
        $app->booted(static function (Application $app): void {

            if (self::isRunningUncheckedCommand($app)) {
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
     * Whether the console command running is one the boot check is skipped for,
     * found as the console finds it: the first argument that is not an option,
     * so `artisan -v mfa:check` is `mfa:check` too.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isRunningUncheckedCommand(Application $app): bool
    {
        return $app->runningInConsole() && in_array((new ArgvInput)->getFirstArgument(), self::UNCHECKED_COMMANDS, true);
    }
}
