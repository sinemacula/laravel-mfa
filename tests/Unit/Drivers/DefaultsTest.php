<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;

/**
 * Assertions against the email driver's constructor default values.
 *
 * Pins the documented defaults so a silent change to any of them trips a
 * mutation-testing signal and a CI diff. The main driver tests exercise
 * behaviour with explicit values; this class locks down the values the driver
 * picks when the consumer supplies none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailDriver::class)]
final class DefaultsTest extends TestCase
{
    /**
     * `EmailDriver`'s constructor default, the `MfaCodeMessage` Mailable, must
     * be preserved.
     *
     * @return void
     */
    public function testEmailDriverDefaults(): void
    {
        $sender = new FakeEmailSender;

        (new EmailDriver(sender: $sender))->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), '123456', CarbonImmutable::now()->addMinutes(5));

        self::assertSame(MfaCodeMessage::class, $sender->sent()[0]['message']::class);
    }
}
