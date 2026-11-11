<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeBindings;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\TestCase;

/**
 * Recovery codes are not a factor, so no driver is registered for them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeBindings::class)]
final class RecoveryCodeBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(RecoveryCodeService::class));
        self::assertTrue($this->container()->bound(RecoveryCodeService::class));
        self::assertNotSame($this->container()->make(RecoveryCodeService::class), $this->container()->make(RecoveryCodeService::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersNoDriverForRecoveryCodes(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
        self::assertArrayNotHasKey(RecoveryCodeService::TYPE, $manager->getDrivers());

        $this->expectException(\InvalidArgumentException::class);

        $manager->driver(RecoveryCodeService::TYPE);
    }
}
