<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeBindings;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\TestCase;

/**
 * Tests for `RecoveryCodeBindings`: the backup-code service is shared, the
 * backup-code driver is registered against the manager, and its factory reads
 * its slice of config with the documented defaults.
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
     * The backup-code service is a singleton.
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
     * The resolved manager has the backup-code driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheDriverWithTheManager(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
        self::assertInstanceOf(BackupCodeDriver::class, $manager->driver(BackupCodeDriver::NAME));
    }

    /**
     * The driver registered against a manager reads the application's config.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExtendRegistersADriverThatReadsTheConfig(): void
    {
        config()->set('mfa.recovery_codes.count', 4);

        $manager = new MfaManager($this->container());

        RecoveryCodeBindings::extend($manager, $this->container());

        $driver = $manager->driver(BackupCodeDriver::NAME);

        self::assertInstanceOf(BackupCodeDriver::class, $driver);
        self::assertSame(4, $driver->getCodeCount());
    }

    /**
     * The factory applies the documented defaults.
     *
     * @return void
     */
    public function testFactoryAppliesTheDefaults(): void
    {
        $driver = RecoveryCodeBindings::backupCodes(new Repository);

        self::assertSame(12, $driver->getCodeLength());
        self::assertSame('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', $driver->getAlphabet());
        self::assertSame(10, $driver->getCodeCount());
    }

    /**
     * The factory reads every configured value.
     *
     * @return void
     */
    public function testFactoryReadsTheConfig(): void
    {
        $driver = RecoveryCodeBindings::backupCodes(new Repository(['mfa' => ['recovery_codes' => [
            'length'   => 14,
            'alphabet' => 'ABCDEFGH',
            'count'    => 5,
        ]]]));

        self::assertSame(14, $driver->getCodeLength());
        self::assertSame('ABCDEFGH', $driver->getAlphabet());
        self::assertSame(5, $driver->getCodeCount());
    }
}
