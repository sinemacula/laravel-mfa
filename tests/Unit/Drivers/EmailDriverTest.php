<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * Unit tests for `EmailDriver`: its channel, and the message it delivers each
 * code in through the bound `EmailSender`.
 *
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
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An email factor travels by email and adds `otp`.
     *
     * @return void
     */
    public function testTheDriverStatesItsChannel(): void
    {
        $driver = new EmailDriver(new FakeEmailSender);

        self::assertSame(ChannelKind::EMAIL, $driver->channelKind());
        self::assertSame(['otp'], $driver->amr());
    }

    /**
     * The code goes to the factor's address in the shipped message, and no
     * other.
     *
     * @return void
     */
    public function testTheCodeIsDeliveredToTheAddressInTheShippedMessage(): void
    {
        $sender = new FakeEmailSender;

        (new EmailDriver($sender))->deliver(self::factor(), '123456', CarbonImmutable::now()->addMinutes(10));

        $sent = $sender->sent();

        self::assertCount(1, $sent);
        self::assertSame(self::ADDRESS, $sent[0]['to']);
        self::assertInstanceOf(MfaCodeMessage::class, $sent[0]['message']);
        self::assertSame('123456', $sent[0]['message']->code);
    }

    /**
     * A configured message class is the one delivered.
     *
     * @return void
     */
    public function testAConfiguredMessageClassIsDelivered(): void
    {
        $sender = new FakeEmailSender;
        $driver = new EmailDriver($sender, CustomMfaCodeMessage::class);

        $driver->deliver(self::factor(), '654321', CarbonImmutable::now()->addMinutes(10));

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
        self::assertInstanceOf(CustomMfaCodeMessage::class, $sender->sent()[0]['message']);
        self::assertSame('654321', $sender->lastCodeTo(self::ADDRESS));
    }

    /**
     * Rows of `[seconds the code has left, minutes the message states]`.
     *
     * @return iterable<string, array{int, int}>
     */
    public static function lifetimes(): iterable
    {
        yield 'whole minutes' => [600, 10];
        yield 'part of a minute rounds up' => [570, 10];
        yield 'just over a minute' => [61, 2];
        yield 'under a minute is one' => [30, 1];
        yield 'already past is one' => [-5, 1];
    }

    /**
     * The message states the whole minutes, at least one, the code has left.
     *
     * @param  int  $seconds
     * @param  int  $minutes
     * @return void
     */
    #[DataProvider('lifetimes')]
    public function testTheMessageStatesTheMinutesTheCodeHasLeft(int $seconds, int $minutes): void
    {
        $now = CarbonImmutable::parse('2026-11-01 12:00:00');

        CarbonImmutable::setTestNow($now);

        $sender = new FakeEmailSender;

        (new EmailDriver($sender))->deliver(self::factor(), '123456', $now->addSeconds($seconds));

        $message = $sender->sent()[0]['message'];

        self::assertInstanceOf(MfaCodeMessage::class, $message);
        self::assertSame($minutes, $message->expiresInMinutes);
    }

    /**
     * An email factor.
     *
     * @return \Tests\Fixtures\Factors\InMemoryFactor
     */
    private static function factor(): InMemoryFactor
    {
        return new InMemoryFactor(type: 'email', destination: self::ADDRESS);
    }
}
