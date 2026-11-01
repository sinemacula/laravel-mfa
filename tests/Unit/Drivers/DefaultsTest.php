<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Contracts\Mail\Mailer;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Testing\FakeSmsGateway;

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
#[CoversClass(AbstractOtpDriver::class)]
#[CoversClass(BackupCodeDriver::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
final class DefaultsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * `AbstractOtpDriver`'s constructor defaults — code length 6 and a
     * 10-minute expiry — must be preserved.
     *
     * @return void
     */
    public function testAbstractOtpDriverDefaults(): void
    {
        $driver = new class extends AbstractOtpDriver {
            /**
             * The channel kind is irrelevant to the defaults.
             *
             * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
             */
            #[\Override]
            public function channelKind(): ChannelKind
            {
                return ChannelKind::EMAIL;
            }

            /**
             * No-op dispatch — the test only asserts the constructor defaults
             * exposed via the getters.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
             * @param  string  $code
             * @return void
             */
            #[\Override]
            protected function dispatch(EloquentFactor $factor, #[\SensitiveParameter] string $code): void
            {
                // Intentionally empty — see method docblock.
            }
        };

        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
    }

    /**
     * `EmailDriver`'s constructor defaults — code length 6, 10-minute expiry
     * and the default `MfaCodeMessage` Mailable — must be preserved.
     *
     * @return void
     */
    public function testEmailDriverDefaults(): void
    {
        /** @var \Illuminate\Contracts\Mail\Mailer&\Mockery\MockInterface $mailer */
        $mailer = \Mockery::mock(Mailer::class);

        $driver = new EmailDriver(mailer: $mailer);

        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * `SmsDriver`'s constructor defaults — code length 6, 10-minute expiry and
     * the shipped message template — must be preserved.
     *
     * @return void
     */
    public function testSmsDriverDefaults(): void
    {
        $driver = new SmsDriver(gateway: new FakeSmsGateway);

        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
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
}
