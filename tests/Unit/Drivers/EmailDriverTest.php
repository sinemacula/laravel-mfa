<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailDriver::class)]
final class EmailDriverTest extends TestCase
{
    /** @var string The address the factor delivers to. */
    private const string ADDRESS = 'ada@example.test';

    /**
     * @return void
     */
    public function testTheDriverStatesItsChannel(): void
    {
        $driver = new EmailDriver(new FakeEmailSender);

        self::assertSame(ChannelKind::EMAIL, $driver->channelKind());
        self::assertSame(['otp'], $driver->amr());
    }

    /**
     * @return void
     */
    public function testAnAddressIsNormalized(): void
    {
        $driver = new EmailDriver(new FakeEmailSender);

        self::assertSame('ada@example.test', $driver->normalizeDestination("  Ada@Example.TEST\n"));
        self::assertSame('émile@example.test', $driver->normalizeDestination('ÉMILE@example.test'));
        self::assertNull($driver->normalizeDestination('ada.example.test'));
        self::assertNull($driver->normalizeDestination(''));
    }

    /**
     * @return void
     */
    public function testTheMessageIsHandedToTheSender(): void
    {
        $sender  = new FakeEmailSender;
        $message = CodeMessages::to(self::ADDRESS);

        (new EmailDriver($sender))->deliver(self::factor(), $message);

        self::assertSame([$message], $sender->sent());
    }

    /**
     * @return \Tests\Fixtures\Factors\InMemoryFactor
     */
    private static function factor(): InMemoryFactor
    {
        return new InMemoryFactor(type: 'email', destination: self::ADDRESS);
    }
}
