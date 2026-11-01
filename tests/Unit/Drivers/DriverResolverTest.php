<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\NoopFactorDriver;
use Tests\TestCase;

/**
 * Tests for `DriverResolver`: drivers come from the manager's registry, a
 * driver that is not a `FactorDriver` is refused, and a factor is only run
 * through its own driver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DriverResolver::class)]
final class DriverResolverTest extends TestCase
{
    /**
     * The resolver returns the manager's driver for the name, including one a
     * consumer registered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvesTheManagersDriver(): void
    {
        $custom = new NoopFactorDriver;

        $this->manager()->extend('custom', fn (): NoopFactorDriver => $custom);

        self::assertSame($this->manager()->driver('totp'), $this->resolver()->driver('totp'));
        self::assertInstanceOf(TotpDriver::class, $this->resolver()->resolve('totp'));
        self::assertSame($custom, $this->resolver()->resolve('custom'));
    }

    /**
     * A registered driver that is not a `FactorDriver` is returned as it is by
     * `driver()` and refused by `resolve()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesADriverThatIsNotAFactorDriver(): void
    {
        $other = new \stdClass;

        $this->manager()->extend('other', fn (): \stdClass => $other);

        self::assertSame($other, $this->resolver()->driver('other'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Driver [other] must implement SineMacula\Laravel\Mfa\Contracts\FactorDriver.');

        $this->resolver()->resolve('other');
    }

    /**
     * A factor matches the driver it was registered against.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAcceptsTheFactorsOwnDriver(): void
    {
        $this->resolver()->assertMatchesFactor('email', new InMemoryFactor(driver: 'email'));

        // Reaching this line without a mismatch exception is the assertion.
        $this->addToAssertionCount(1);
    }

    /**
     * A factor is refused for any other driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesAnotherDriver(): void
    {
        $this->expectException(FactorDriverMismatchException::class);

        $this->resolver()->assertMatchesFactor('totp', new InMemoryFactor(driver: 'email'));
    }

    /**
     * Resolve the driver resolver.
     *
     * @return \SineMacula\Laravel\Mfa\Drivers\DriverResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): DriverResolver
    {
        return $this->container()->make(DriverResolver::class);
    }

    /**
     * Resolve the package's MFA manager.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
