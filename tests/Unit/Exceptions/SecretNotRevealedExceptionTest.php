<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;

/**
 * Unit tests for the `SecretNotRevealedException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretNotRevealedException::class)]
final class SecretNotRevealedExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        self::assertTrue((new \ReflectionClass(SecretNotRevealedException::class))->isFinal());
    }

    /**
     * Reaching for a secret's plaintext the wrong way is a bug in the calling
     * code, so the exception is a logic exception.
     *
     * @return void
     */
    public function testExtendsLogicException(): void
    {
        self::assertInstanceOf(\LogicException::class, new SecretNotRevealedException('A secret cannot be serialised.'));
    }
}
