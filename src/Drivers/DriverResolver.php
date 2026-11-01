<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

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
