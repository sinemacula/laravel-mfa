<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;

/**
 * Checks the configuration after boot, so bindings made in a provider's
 * `boot()` count. In the console only workers are checked, so any other
 * command, a composing package's own check included, can still run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigurationBindings
{
    /** @var list<string> Checked as they start; any other command runs, so a bad configuration can be repaired. */
    private const array WORKER_COMMANDS = [
        'queue:work',
        'queue:listen',
        'horizon',
        'horizon:supervisor',
        'horizon:work',
        'schedule:run',
        'schedule:work',
        'schedule:test',
        'octane:start',
        'octane:frankenphp',
        'octane:roadrunner',
        'octane:swoole',
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Checks once booted for a request, and in the console only as a worker
     * command starts, matched by the name Artisan resolved.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function boot(Application $app): void
    {
        if (!$app->runningInConsole()) {
            $app->booted(static fn (Application $app) => self::validate($app));

            return;
        }

        $app->make(Dispatcher::class)->listen(CommandStarting::class, static function (CommandStarting $event) use ($app): void {
            if (!in_array($event->command, self::WORKER_COMMANDS, true)) {
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
}
