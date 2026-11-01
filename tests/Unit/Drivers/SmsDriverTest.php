<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * Unit tests for `SmsDriver`: its channel, and the message it delivers each
 * code in through the bound `SmsSender`.
 *
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
     * An SMS factor travels by SMS and adds `sms`.
     *
     * @return void
     */
    public function testTheDriverStatesItsChannel(): void
    {
        $driver = new SmsDriver(new FakeSmsSender);

        self::assertSame(ChannelKind::SMS, $driver->channelKind());
        self::assertSame(['sms'], $driver->amr());
    }

    /**
     * The code goes to the factor's phone number in the shipped message.
     *
     * @return void
     */
    public function testTheCodeIsDeliveredToThePhoneNumberInTheShippedMessage(): void
    {
        $sender = new FakeSmsSender;

        (new SmsDriver($sender))->deliver(self::factor(), '123456', CarbonImmutable::now()->addMinutes(10));

        self::assertSame([['to' => self::PHONE, 'message' => 'Your verification code is: 123456']], $sender->sent());
    }

    /**
     * A configured message has every placeholder replaced with the code.
     *
     * @return void
     */
    public function testAConfiguredMessageHasEveryPlaceholderReplaced(): void
    {
        $sender = new FakeSmsSender;
        $driver = new SmsDriver($sender, ':code is your code. Again: :code');

        $driver->deliver(self::factor(), '654321', CarbonImmutable::now()->addMinutes(10));

        self::assertSame(':code is your code. Again: :code', $driver->getMessageTemplate());
        self::assertSame('654321 is your code. Again: 654321', $sender->lastMessageTo(self::PHONE));
    }

    /**
     * An SMS factor.
     *
     * @return \Tests\Fixtures\Factors\InMemoryFactor
     */
    private static function factor(): InMemoryFactor
    {
        return new InMemoryFactor(type: 'sms', destination: self::PHONE);
    }
}
