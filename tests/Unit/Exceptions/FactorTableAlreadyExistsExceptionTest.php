<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\FactorTableAlreadyExistsException;

/**
 * Unit tests for the `FactorTableAlreadyExistsException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class FactorTableAlreadyExistsExceptionTest extends TestCase
{
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(FactorTableAlreadyExistsException::class);

        self::assertTrue($reflection->isFinal());
    }

    public function testExtendsRuntimeException(): void
    {
        self::assertInstanceOf(
            \RuntimeException::class,
            new FactorTableAlreadyExistsException('boom'),
        );
    }

    public function testPreservesMessage(): void
    {
        $exception = new FactorTableAlreadyExistsException('table collision detected');

        self::assertSame('table collision detected', $exception->getMessage());
    }
}
