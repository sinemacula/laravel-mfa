<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException;

/**
 * Unit tests for the `MissingRecipientException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MissingRecipientExceptionTest extends TestCase
{
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(MissingRecipientException::class);

        self::assertTrue($reflection->isFinal());
    }

    public function testExtendsRuntimeException(): void
    {
        self::assertInstanceOf(
            \RuntimeException::class,
            new MissingRecipientException('missing recipient'),
        );
    }

    public function testPreservesMessage(): void
    {
        $exception = new MissingRecipientException('Recipient required.');

        self::assertSame('Recipient required.', $exception->getMessage());
    }
}
