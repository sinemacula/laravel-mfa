<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
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
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
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
}
