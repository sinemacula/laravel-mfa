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

        $gateway->send('+15551234567', 'hello');
        $gateway->send('+447700900000', 'world');

        self::assertSame([
            ['to' => '+15551234567', 'message' => 'hello'],
            ['to' => '+447700900000', 'message' => 'world'],
        ], $gateway->sent());
    }

    public function testSentToFiltersByRecipient(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send('+15551234567', 'first');
        $gateway->send('+447700900000', 'second');
        $gateway->send('+15551234567', 'third');

        self::assertSame([
            ['to' => '+15551234567', 'message' => 'first'],
            ['to' => '+15551234567', 'message' => 'third'],
        ], $gateway->sentTo('+15551234567'));
    }

    public function testSentToReturnsEmptyWhenNoMatch(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send('+15551234567', 'hello');

        self::assertSame([], $gateway->sentTo('+447700900000'));
    }

    public function testResetClearsRecordedMessages(): void
    {
        $gateway = new FakeSmsGateway;

        $gateway->send('+15551234567', 'hello');
        $gateway->reset();

        self::assertSame([], $gateway->sent());
    }
}
