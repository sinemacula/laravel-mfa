<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Gateways\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;

/**
 * Assertions against each driver's constructor default values.
 *
 * Pins the documented defaults so a silent change to any of them
 * trips a mutation-testing signal and a CI diff. The main driver
 * tests exercise behaviour with explicit values; this class locks
 * down the values the drivers pick when the consumer supplies none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class DefaultsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * `AbstractOtpDriver`'s constructor defaults — code length 6,
     * 10-minute expiry, 3 attempts, no custom alphabet — must be
     * preserved.
     *
     * @return void
     */
    public function testAbstractOtpDriverDefaults(): void
    {
        $driver = new class extends AbstractOtpDriver {
            /**
             * No-op dispatch — the test only asserts the
             * constructor defaults exposed via the getters.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
             * @param  string  $code
             * @return void
             */
            protected function dispatch(
                \SineMacula\Laravel\Mfa\Contracts\EloquentFactor $factor,
                #[\SensitiveParameter]
                string $code,
            ): void {
                // Intentionally empty — see method docblock.
            }
        };

        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    /**
     * `EmailDriver`'s constructor defaults — code length 6,
     * 10-minute expiry, 3 attempts, default `MfaCodeMessage`
     * Mailable, no custom alphabet — must be preserved.
     *
     * @return void
     */
    public function testEmailDriverDefaults(): void
    {
        /** @var \Illuminate\Contracts\Mail\Mailer&\Mockery\MockInterface $mailer */
        $mailer = \Mockery::mock(\Illuminate\Contracts\Mail\Mailer::class);

        $driver = new EmailDriver(mailer: $mailer);

        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
        self::assertNull($driver->getAlphabet());
    }

    /**
     * `SmsDriver`'s constructor defaults — code length 6, 10-minute
     * expiry, 3 attempts, the shipped message template, no custom
     * alphabet — must be preserved.
     *
     * @return void
     */
    public function testSmsDriverDefaults(): void
    {
        $driver = new SmsDriver(gateway: new FakeSmsGateway);

        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertSame(
            'Your verification code is: :code',
            $driver->getMessageTemplate(),
        );
        self::assertNull($driver->getAlphabet());
    }

    /**
     * `BackupCodeDriver`'s constructor defaults — 10-character
     * codes, the shipped Crockford-style alphabet, and a set size of
     * 10 — must be preserved.
     *
     * @return void
     */
    public function testBackupCodeDriverDefaults(): void
    {
        $driver = new BackupCodeDriver;

        self::assertSame(10, $driver->getCodeLength());
        self::assertSame('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', $driver->getAlphabet());
        self::assertSame(10, $driver->getCodeCount());
    }

    /**
     * The TOTP driver's default window must be 1 — observed via
     * reflection on the private `window` property since the value is
     * never exposed via a getter.
     *
     * @return void
     */
    public function testTotpDriverDefaultsWindowToOne(): void
    {
        $driver = new TotpDriver;

        $property = new \ReflectionProperty($driver, 'window');

        // Reflection on the private `window` property is the only way
        // to observe the constructor default value — the driver does
        // not expose a public getter, and we explicitly do NOT want a
        // behavioural test here that would cross into Google2FA's
        // verifyKey window logic (covered in its own dependency tests).
        // @SuppressWarnings("php:S3011")
        self::assertSame(1, $property->getValue($driver));
    }
}
