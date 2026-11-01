<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;

/**
 * Resolves factor drivers from the manager's driver registry for the services
 * that run a factor through its driver.
 *
 * The registry is the `mfa` manager, read from the container on every call so
 * the drivers registered with `Mfa::extend()` are the ones used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DriverResolver
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the manager is read from. */
        private Container $container,
    ) {}

    /**
     * Return the named driver exactly as the manager builds it.
     *
     * @param  string  $name
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function driver(string $name): mixed
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager $manager */
        $manager = $this->container->make('mfa');

        return $manager->driver($name);
    }

    /**
     * Resolve the named factor driver, narrowed to the `FactorDriver` contract
     * for downstream callers.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     *
     * @throws \LogicException
     */
    public function resolve(string $name): FactorDriver
    {
        $instance = $this->driver($name);

        if (!$instance instanceof FactorDriver) {
            throw new \LogicException(sprintf('Driver [%s] must implement %s.', $name, FactorDriver::class));
        }

        return $instance;
    }

    /**
     * Verify that the requested driver name matches the factor's own
     * `getDriver()`.
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
        if ($driver !== $factor->getDriver()) {
            throw FactorDriverMismatchException::for($driver, $factor);
        }
    }
}
