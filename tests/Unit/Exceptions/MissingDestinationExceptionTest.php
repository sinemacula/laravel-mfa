<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;

/**
 * Unit tests for the `MissingDestinationException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MissingDestinationException::class)]
final class MissingDestinationExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(MissingDestinationException::class);

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
            new MissingDestinationException('missing destination'),
        );
    }

    /**
     * Test preserves message.
     *
     * @return void
     */
    public function testPreservesMessage(): void
    {
        $exception = new MissingDestinationException('Destination required.');

        self::assertSame('Destination required.', $exception->getMessage());
    }
}
