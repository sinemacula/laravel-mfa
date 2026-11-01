<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\Manager;

/**
 * Binds a fake sender in place of the application's, and makes the manager
 * build its drivers again: a driver keeps the sender it was built with, so one
 * resolved before the fake would otherwise go on sending through the old one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FakeSenderBinding
{
    /**
     * Prevent instantiation.
     */
    private function __construct() {}

    /**
     * Bind the fake as the sender contract in the container (the application's,
     * when none is given), and forget the drivers of the `mfa` manager when it
     * has already been built.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @param  class-string  $contract
     * @param  object  $fake
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function bind(?ContainerContract $container, string $contract, object $fake): void
    {
        $container ??= Container::getInstance();

        $container->instance($contract, $fake);

        $manager = $container->resolved('mfa') ? $container->make('mfa') : null;

        if (!$manager instanceof Manager) {
            return;
        }

        $manager->forgetDrivers();
    }
}
