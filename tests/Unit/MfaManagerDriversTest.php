<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;

/**
 * Unit tests for the `MfaManager` driver factories exposed via
 * `driver($name)`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerDriversTest extends MfaManagerTestCase
{
    public function testTotpDriverBuildsWithConfiguredWindow(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.totp.window', 3);

        $driver = $this->manager()->driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);
    }

    public function testTotpDriverDefaultsWindowToOneWhenUnset(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.totp', []);

        $driver = $this->manager()->driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);
    }

    public function testEmailDriverBuildsWithDefaults(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.email', []);

        /** @var EmailDriver $driver */
        $driver = $this->manager()->driver('email');

        self::assertInstanceOf(EmailDriver::class, $driver);
        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    public function testEmailDriverBuildsWithConfiguredOverrides(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.email', [
            'code_length'  => 8,
            'expiry'       => 20,
            'max_attempts' => 7,
            'alphabet'     => '0123456789ABCDEF',
            'mailable'     => \SineMacula\Laravel\Mfa\Mail\MfaCodeMessage::class,
        ]);

        /** @var EmailDriver $driver */
        $driver = $this->manager()->driver('email');

        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(20, $driver->getExpiry());
        self::assertSame(7, $driver->getMaxAttempts());
        self::assertSame('0123456789ABCDEF', $driver->getAlphabet());
    }

    public function testSmsDriverBuildsWithDefaults(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.sms', []);

        /** @var SmsDriver $driver */
        $driver = $this->manager()->driver('sms');

        self::assertInstanceOf(SmsDriver::class, $driver);
        self::assertSame('Your verification code is: :code', $driver->getMessageTemplate());
        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    public function testSmsDriverBuildsWithConfiguredOverrides(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.sms', [
            'code_length'      => 4,
            'expiry'           => 5,
            'max_attempts'     => 2,
            'alphabet'         => 'ABCDEF',
            'message_template' => 'Code: :code',
        ]);

        /** @var SmsDriver $driver */
        $driver = $this->manager()->driver('sms');

        self::assertSame('Code: :code', $driver->getMessageTemplate());
        self::assertSame(4, $driver->getCodeLength());
        self::assertSame(5, $driver->getExpiry());
        self::assertSame(2, $driver->getMaxAttempts());
        self::assertSame('ABCDEF', $driver->getAlphabet());
    }

    public function testBackupCodeDriverBuildsWithDefaults(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.backup_code', []);

        /** @var BackupCodeDriver $driver */
        $driver = $this->manager()->driver('backup_code');

        self::assertInstanceOf(BackupCodeDriver::class, $driver);
        self::assertSame(10, $driver->getCodeLength());
        self::assertSame('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', $driver->getAlphabet());
        self::assertSame(10, $driver->getCodeCount());
    }

    public function testBackupCodeDriverBuildsWithConfiguredOverrides(): void
    {
        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.backup_code', [
            'code_length' => 12,
            'alphabet'    => 'ABCDEF',
            'code_count'  => 5,
        ]);

        /** @var BackupCodeDriver $driver */
        $driver = $this->manager()->driver('backup_code');

        self::assertSame(12, $driver->getCodeLength());
        self::assertSame('ABCDEF', $driver->getAlphabet());
        self::assertSame(5, $driver->getCodeCount());
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function manager(): MfaManager
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager $manager */
        return $this->app->make('mfa');
    }
}
