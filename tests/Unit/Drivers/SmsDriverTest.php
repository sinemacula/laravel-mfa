<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SmsDriver::class)]
final class SmsDriverTest extends TestCase
{
    /** @var string The phone number the factor delivers to. */
    private const string PHONE = '+447700900123';

    /**
     * @return void
     */
    public function testTheDriverStatesItsChannel(): void
    {
        $driver = new SmsDriver(new FakeSmsSender);

        self::assertSame(ChannelKind::SMS, $driver->channelKind());
        self::assertSame(['sms'], $driver->amr());
    }

    /**
     * No country code is assumed.
     *
     * @return void
     */
    public function testAPhoneNumberIsNormalized(): void
    {
        $driver = new SmsDriver(new FakeSmsSender);

        self::assertSame(self::PHONE, $driver->normalizeDestination(' +44 (7700)-900 123 '));
        self::assertSame('+12345678', $driver->normalizeDestination('+12345678'));
        self::assertSame('+123456789012345', $driver->normalizeDestination('+123456789012345'));

        foreach (['07700900123', '+1234567', '+1234567890123456', '+01234567890', '+4477009001x', "+447700900123\n", ''] as $invalid) {
            self::assertNull($driver->normalizeDestination($invalid), $invalid);
        }
    }

    /**
     * @return void
     */
    public function testTheMessageIsHandedToTheSender(): void
    {
        $sender  = new FakeSmsSender;
        $message = CodeMessages::to(self::PHONE, type: 'sms');

        (new SmsDriver($sender))->deliver(self::factor(), $message);

        self::assertSame([$message], $sender->sent());
    }

    /**
     * @return \Tests\Fixtures\Factors\InMemoryFactor
     */
    private static function factor(): InMemoryFactor
    {
        return new InMemoryFactor(type: 'sms', destination: self::PHONE);
    }
}
