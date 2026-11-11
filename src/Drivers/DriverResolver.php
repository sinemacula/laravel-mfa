<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;

/**
 * Resolves factor drivers from the `mfa` manager on every call, so a driver
 * registered with `extend()` is the one used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DriverResolver
{
    /**
     * @param  \Illuminate\Support\Manager  $registry
     * @param  string  $name
     * @return mixed
     */
    public function driver(Manager $registry, string $name): mixed
    {
        return $registry->driver($name);
    }

    /**
     * @param  \Illuminate\Support\Manager  $registry
     * @param  string  $name
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \LogicException
     */
    public function resolve(Manager $registry, string $name): FactorDriver
    {
        $instance = $this->driver($registry, $name);

        if (!$instance instanceof FactorDriver) {
            throw new \LogicException(sprintf('Driver [%s] must implement %s.', $name, FactorDriver::class));
        }

        return $instance;
    }

    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $name
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public function fromContainer(Container $container, string $name): FactorDriver
    {
        $registry = $container->make('mfa');

        if (!$registry instanceof Manager) {
            throw new \LogicException('The [mfa] binding must be the MFA manager.');
        }

        return $this->resolve($registry, $name);
    }
}
