<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;

/**
 * Binds the default `EventContextResolver`, which an authentication layer or
 * the application rebinds, and the event dispatcher.
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
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(EventContextResolver::class, DefaultEventContextResolver::class);
        $app->bindIf(EventDispatcher::class);
    }
}
