<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Console\CheckConfigurationCommand;
use Symfony\Component\Console\Input\ArgvInput;

/**
 * Checks the configuration after boot, so bindings made in a provider's
 * `boot()` count. Skipped for `mfa:check` and configuration maintenance
 * commands, so a broken configuration can still be inspected and cleared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigurationBindings
{
    /** @var list<string> */
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
     * The first non-option argument, so `artisan -v mfa:check` matches too.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isRunningUncheckedCommand(Application $app): bool
    {
        return $app->runningInConsole() && in_array((new ArgvInput)->getFirstArgument(), self::UNCHECKED_COMMANDS, true);
    }
}
