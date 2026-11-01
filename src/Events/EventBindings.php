<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;

/**
 * Registers the event wiring: the default `EventContextResolver`, which an
 * authentication layer's adapter or the application rebinds, and the dispatcher
 * every event goes through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EventBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the default context resolver and the dispatcher.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(EventContextResolver::class, DefaultEventContextResolver::class);
        $app->singleton(EventDispatcher::class);
    }
}
