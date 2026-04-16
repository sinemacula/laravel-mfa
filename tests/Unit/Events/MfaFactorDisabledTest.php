<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;

/**
 * Unit tests for the `MfaFactorDisabled` event DTO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaFactorDisabledTest extends TestCase
{
    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(MfaFactorDisabled::class);

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
    }

    public function testConstructorPreservesArguments(): void
    {
        $identity = self::createStub(Authenticatable::class);
        $factor   = self::createStub(Factor::class);

        $event = new MfaFactorDisabled($identity, $factor, 'totp');

        self::assertSame($identity, $event->identity);
        self::assertSame($factor, $event->factor);
        self::assertSame('totp', $event->driver);
    }
}
