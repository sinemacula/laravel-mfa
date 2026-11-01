<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException;

/**
 * Unit tests for the `TableAlreadyExistsException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TableAlreadyExistsException::class)]
final class TableAlreadyExistsExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(TableAlreadyExistsException::class);

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
            new TableAlreadyExistsException('boom'),
        );
    }

    /**
     * Test preserves message.
     *
     * @return void
     */
    public function testPreservesMessage(): void
    {
        $exception = new TableAlreadyExistsException('table collision detected');

        self::assertSame('table collision detected', $exception->getMessage());
    }
}
