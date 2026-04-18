<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Events\MfaVerified;

/**
 * Unit tests for the `MfaVerified` event DTO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaVerifiedTest extends TestCase
{
    /**
     * Test is final readonly class.
     *
     * @return void
     */
    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(MfaVerified::class);

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
    }

    /**
     * Test constructor preserves arguments.
     *
     * @return void
     */
    public function testConstructorPreservesArguments(): void
    {
        $identity = self::createStub(Authenticatable::class);
        $factor   = self::createStub(Factor::class);

        $event = new MfaVerified($identity, $factor, 'email');

        self::assertSame($identity, $event->identity);
        self::assertSame($factor, $event->factor);
        self::assertSame('email', $event->driver);
    }
}
