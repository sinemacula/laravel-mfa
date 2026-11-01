<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Log\Logger;
use Illuminate\Routing\Router;

/**
 * Wires the handling of secrets into the application when the package boots:
 * the `mfa.no-store` middleware alias, and, unless `mfa.secrets.redact` is off,
 * the `RedactSecretsInLogs` tap on every configured log channel and every
 * channel resolved already, and the scrubbing of every exception the exception
 * handler reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecretBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Alias the middleware and, while redaction is on, redact secrets from logs
     * and reported exceptions.
     *
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function boot(Container $app): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $app->make(Router::class);

        $router->aliasMiddleware('mfa.no-store', NoStore::class);

        $config = $app->make(Repository::class);

        if (!(new SecretSettings($config))->redacts()) {
            return;
        }

        self::tapLogChannels($config);
        self::tapResolvedChannels($app);
        self::scrubReportedExceptions($app);
    }

    /**
     * Add the redacting tap to every configured log channel that does not list
     * it yet. A channel whose `tap` is not a list is left as it is.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return void
     */
    private static function tapLogChannels(Repository $config): void
    {
        $channels = $config->get('logging.channels');

        if (!is_array($channels)) {
            return;
        }

        foreach ($channels as $name => $channel) {
            if (!is_array($channel)) {
                continue;
            }

            $taps = $channel['tap'] ?? [];

            if (!is_array($taps) || in_array(RedactSecretsInLogs::class, $taps, true)) {
                continue;
            }

            $taps[]          = RedactSecretsInLogs::class;
            $channel['tap']  = $taps;
            $channels[$name] = $channel;
        }

        $config->set('logging.channels', $channels);
    }

    /**
     * Apply the redacting tap to every channel the log manager resolved before
     * the package booted, which it keeps and never taps again.
     *
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function tapResolvedChannels(Container $app): void
    {
        if (!$app->resolved('log')) {
            return;
        }

        /** @var \Illuminate\Log\LogManager $log */
        $log = $app->make('log');

        foreach ($log->getChannels() as $channel) {
            if (!$channel instanceof Logger) {
                continue;
            }

            (new RedactSecretsInLogs)($channel);
        }
    }

    /**
     * Scrub every exception the exception handler reports before it is logged,
     * whether the handler is built already or later.
     *
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function scrubReportedExceptions(Container $app): void
    {
        if ($app->resolved(ExceptionHandler::class)) {
            self::scrubReportsOf($app->make(ExceptionHandler::class));

            return;
        }

        $app->afterResolving(ExceptionHandler::class, static function (mixed $handler): void {
            self::scrubReportsOf($handler);
        });
    }

    /**
     * Have the handler scrub every exception it reports, when it is Laravel's.
     *
     * @param  mixed  $handler
     * @return void
     */
    private static function scrubReportsOf(mixed $handler): void
    {
        if (!$handler instanceof Handler) {
            return;
        }

        $handler->reportable(static function (\Throwable $throwable): void {
            ExceptionScrubber::scrub($throwable);
        });
    }
}
