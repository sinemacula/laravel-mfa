<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\MissingDriverDependencyException;

/**
 * Unit tests for the `MissingDriverDependencyException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MissingDriverDependencyExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(MissingDriverDependencyException::class);

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
            new MissingDriverDependencyException('missing'),
        );
    }

    /**
     * Test preserves message.
     *
     * @return void
     */
    public function testPreservesMessage(): void
    {
        $exception = new MissingDriverDependencyException('install pragmarx/google2fa');

        self::assertSame('install pragmarx/google2fa', $exception->getMessage());
    }
}
