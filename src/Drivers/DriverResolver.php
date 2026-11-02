<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;

/**
 * Resolves factor drivers from a manager's driver registry for the services
 * that run a factor through its driver.
 *
 * The registry is passed in on every call: it is the manager the operation was
 * called on, so the drivers registered against that manager with `extend()` are
 * the ones used, whether it is the `mfa` singleton or a manager built
 * separately.
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
     * Verify that the requested driver name matches the factor's own
     * `getType()`.
     *
     * Routing one driver's logic through a factor that was registered against
     * another is a caller bug: it does not bypass ownership (that check still
     * runs) but it would produce confusing persistence, transport, and
     * audit-event semantics, for example verifying an email-factor row with the
     * TOTP driver. Fail loudly so the mistake cannot hide.
     *
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     */
    public function assertMatchesFactor(string $driver, Factor $factor): void
    {
        if ($driver !== $factor->getType()) {
            throw FactorDriverMismatchException::for($driver, $factor);
        }
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
