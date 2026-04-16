<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Unit tests for the `UnsupportedIdentifierException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class UnsupportedIdentifierExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(UnsupportedIdentifierException::class);

        self::assertTrue($reflection->isFinal());
    }

    /**
     * Test extends runtime exception.
     *
     * @return void
     */
    public function testExtendsRuntimeException(): void
    {
        self::assertInstanceOf(
            \RuntimeException::class,
            new UnsupportedIdentifierException('unsupported'),
        );
    }

    /**
     * Test preserves message.
     *
     * @return void
     */
    public function testPreservesMessage(): void
    {
        $exception = new UnsupportedIdentifierException('Scalar identifier required.');

        self::assertSame('Scalar identifier required.', $exception->getMessage());
    }
}
