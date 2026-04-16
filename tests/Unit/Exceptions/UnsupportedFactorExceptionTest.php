<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;

/**
 * Unit tests for the `UnsupportedFactorException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class UnsupportedFactorExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(UnsupportedFactorException::class);

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
            new UnsupportedFactorException('unsupported'),
        );
    }

    /**
     * Test preserves message.
     *
     * @return void
     */
    public function testPreservesMessage(): void
    {
        $exception = new UnsupportedFactorException('Persistable factor required.');

        self::assertSame('Persistable factor required.', $exception->getMessage());
    }
}
