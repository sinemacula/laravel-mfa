<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;

/**
 * Binds a fake sender in place of the application's: the manager builds its
 * drivers on every call, so the next driver built sends through the fake.
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
     * Bind the fake as the sender contract in the container, the application's
     * when none is given.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @param  class-string  $contract
     * @param  object  $fake
     * @return void
     */
    public static function bind(?ContainerContract $container, string $contract, object $fake): void
    {
        ($container ?? Container::getInstance())->instance($contract, $fake);
    }
}
