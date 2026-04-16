<?php

declare(strict_types = 1);

namespace Tests\Unit\Gateways;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Gateways\FakeSmsGateway;

/**
 * Unit tests for the `FakeSmsGateway` in-memory test double.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class FakeSmsGatewayTest extends TestCase
{
    /** @var string */
    private const string US_NUMBER = '+15551234567';

    /** @var string */
    private const string UK_NUMBER = '+447700900000';

    public function testImplementsSmsGatewayContract(): void
    {
        self::assertInstanceOf(SmsGateway::class, new FakeSmsGateway);
    }

    public function testSentIsInitiallyEmpty(): void
    {
        $gateway = new FakeSmsGateway;

        self::assertSame([], $gateway->sent());
    }

    public function testSendRecordsOutboundMessages(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send(self::US_NUMBER, 'hello');
        $gateway->send(self::UK_NUMBER, 'world');

        self::assertSame([
            ['to' => self::US_NUMBER, 'message' => 'hello'],
            ['to' => self::UK_NUMBER, 'message' => 'world'],
        ], $gateway->sent());
    }

    public function testSentToFiltersByRecipient(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send(self::US_NUMBER, 'first');
        $gateway->send(self::UK_NUMBER, 'second');
        $gateway->send(self::US_NUMBER, 'third');

        self::assertSame([
            ['to' => self::US_NUMBER, 'message' => 'first'],
            ['to' => self::US_NUMBER, 'message' => 'third'],
        ], $gateway->sentTo(self::US_NUMBER));
    }

    public function testSentToReturnsEmptyWhenNoMatch(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send(self::US_NUMBER, 'hello');

        self::assertSame([], $gateway->sentTo(self::UK_NUMBER));
    }

    public function testResetClearsRecordedMessages(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send(self::US_NUMBER, 'hello');
        $gateway->reset();

        self::assertSame([], $gateway->sent());
    }
}
