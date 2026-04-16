<?php

declare(strict_types = 1);

namespace Tests\Unit\Gateways;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Exceptions\SmsGatewayNotConfiguredException;
use SineMacula\Laravel\Mfa\Gateways\NullSmsGateway;

/**
 * Unit tests for the `NullSmsGateway` default gateway implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class NullSmsGatewayTest extends TestCase
{
    public function testSendAlwaysThrowsSmsGatewayNotConfiguredException(): void
    {
        $gateway = new NullSmsGateway;

        $this->expectException(SmsGatewayNotConfiguredException::class);
        $this->expectExceptionMessage('No SMS gateway is bound.');

        $gateway->send('+15551234567', 'hello');
    }

    public function testImplementsSmsGatewayContract(): void
    {
        self::assertInstanceOf(SmsGateway::class, new NullSmsGateway);
    }
}
