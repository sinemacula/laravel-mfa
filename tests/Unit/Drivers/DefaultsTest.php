<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;

/**
 * Assertions against each driver's constructor default values.
 *
 * Pins the documented defaults so a silent change to any of them trips a
 * mutation-testing signal and a CI diff. The main driver tests exercise
 * behaviour with explicit values; this class locks down the values the drivers
 * pick when the consumer supplies none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BackupCodeDriver::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(TotpDriver::class)]
final class DefaultsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * `EmailDriver`'s constructor default, the `MfaCodeMessage` Mailable, must
     * be preserved.
     *
     * @return void
     */
    public function testEmailDriverDefaults(): void
    {
        $driver = new EmailDriver(sender: new FakeEmailSender);

        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * `SmsDriver`'s constructor default, the shipped message template, must be
     * preserved.
     *
     * @return void
     */
    public function testSmsDriverDefaults(): void
    {
        $driver = new SmsDriver(sender: new FakeSmsSender);

        self::assertSame(
            'Your verification code is: :code',
            $driver->getMessageTemplate(),
        );
    }

    /**
     * `BackupCodeDriver`'s constructor defaults — 12-character codes, the
     * shipped Crockford-style alphabet, and a set size of 10 — must be
     * preserved.
     *
     * @return void
     */
    public function testBackupCodeDriverDefaults(): void
    {
        $driver = new BackupCodeDriver;

        self::assertSame(12, $driver->getCodeLength());
        self::assertSame('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', $driver->getAlphabet());
        self::assertSame(10, $driver->getCodeCount());
    }

    /**
     * The TOTP driver's default window must be 1 — observed via reflection on
     * the private `window` property since the value is never exposed via a
     * getter.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testTotpDriverDefaultsWindowToOne(): void
    {
        $driver = new TotpDriver;

        $property = new \ReflectionProperty($driver, 'window');

        // Reflection on the private `window` property is the only way to
        // observe the constructor default value — the driver does not expose a
        // public getter, and we explicitly do NOT want a behavioural test here
        // that would cross into Google2FA's verifyKey window logic (covered in
        // its own dependency tests). @SuppressWarnings("php:S3011")
        self::assertSame(1, $property->getValue($driver));
    }
}
