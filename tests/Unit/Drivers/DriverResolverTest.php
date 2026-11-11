<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DriverResolver::class)]
final class DriverResolverTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvesTheManagersDriver(): void
    {
        $custom = new NoopFactorDriver;

        $this->manager()->extend('custom', fn (): NoopFactorDriver => $custom);

        self::assertInstanceOf(TotpDriver::class, $this->resolver()->driver($this->manager(), 'totp'));
        self::assertInstanceOf(TotpDriver::class, $this->resolver()->resolve($this->manager(), 'totp'));
        self::assertSame($custom, $this->resolver()->resolve($this->manager(), 'custom'));
    }

    /**
     * A manager built apart from the `mfa` singleton is not answered from the
     * singleton's registry.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvesFromTheRegistryPassedIn(): void
    {
        $own      = new NoopFactorDriver;
        $separate = new MfaManager($this->container());

        $separate->extend('totp', fn (): NoopFactorDriver => $own);

        self::assertSame($own, $this->resolver()->resolve($separate, 'totp'));
        self::assertInstanceOf(TotpDriver::class, $this->resolver()->resolve($this->manager(), 'totp'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesADriverThatIsNotAFactorDriver(): void
    {
        $other = new \stdClass;

        $this->manager()->extend('other', fn (): \stdClass => $other);

        self::assertSame($other, $this->resolver()->driver($this->manager(), 'other'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Driver [other] must implement SineMacula\Laravel\Mfa\Contracts\FactorDriver.');

        $this->resolver()->resolve($this->manager(), 'other');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Drivers\DriverResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): DriverResolver
    {
        return $this->container()->make(DriverResolver::class);
    }

    /**
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
