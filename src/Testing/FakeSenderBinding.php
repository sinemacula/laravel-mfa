<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;

/**
 * Binds a fake sender; drivers are rebuilt per call, so the next one uses it.
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
     * Bind into the given container, or the application's when null.
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
