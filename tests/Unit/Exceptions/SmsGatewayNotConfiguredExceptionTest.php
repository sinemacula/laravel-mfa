<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\SmsGatewayNotConfiguredException;

/**
 * Unit tests for the `SmsGatewayNotConfiguredException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SmsGatewayNotConfiguredExceptionTest extends TestCase
{
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(SmsGatewayNotConfiguredException::class);

        self::assertTrue($reflection->isFinal());
    }

    public function testExtendsRuntimeException(): void
    {
        self::assertInstanceOf(
            \RuntimeException::class,
            new SmsGatewayNotConfiguredException('no gateway'),
        );
    }

    public function testPreservesMessage(): void
    {
        $exception = new SmsGatewayNotConfiguredException('Bind an SmsGateway.');

        self::assertSame('Bind an SmsGateway.', $exception->getMessage());
    }
}
