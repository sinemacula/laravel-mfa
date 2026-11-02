<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;

/**
 * Resolves factor drivers for the services that run a factor through its
 * driver: a factor runs through the driver of the `mfa` manager the container
 * holds, which builds it on every call. A driver registered there with
 * `extend()` is the one used, and a driver keeps no state between calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DriverResolver
{
    /**
     * Return the named driver exactly as the given registry builds it.
     *
     * @param  \Illuminate\Support\Manager  $registry
     * @param  string  $name
     * @return mixed
     */
    public function driver(Manager $registry, string $name): mixed
    {
        return $registry->driver($name);
    }

    /**
     * Resolve the named factor driver from the given registry, narrowed to the
     * `FactorDriver` contract for downstream callers.
     *
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
     * Resolve the named factor driver from the `mfa` manager the container
     * holds, for a service that runs a factor through its type's driver without
     * a manager of its own to hand.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $name
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public function fromContainer(Container $container, string $name): FactorDriver
    {
        return $this->resolve(self::manager($container->make('mfa')), $name);
    }

    /**
     * The registry the `mfa` binding holds, which must be the MFA manager.
     *
     * @param  mixed  $registry
     * @return \Illuminate\Support\Manager
     *
     * @throws \LogicException
     */
    private static function manager(mixed $registry): Manager
    {
        if (!$registry instanceof Manager) {
            throw new \LogicException('The [mfa] binding must be the MFA manager.');
        }

        return $registry;
    }
}
