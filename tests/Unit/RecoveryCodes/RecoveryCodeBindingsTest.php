<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeBindings;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\TestCase;

/**
 * Tests for `RecoveryCodeBindings`: the recovery code service is shared, and
 * no factor driver is registered for recovery codes, which are not a factor.
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
     * The recovery code service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(RecoveryCodeService::class));
        self::assertSame($this->container()->make(RecoveryCodeService::class), $this->container()->make(RecoveryCodeService::class));
    }

    /**
     * The resolved manager has no driver for recovery codes.
     *
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
