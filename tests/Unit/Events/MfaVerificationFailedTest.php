<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;

/**
 * Unit tests for the `MfaVerificationFailed` event DTO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaVerificationFailedTest extends TestCase
{
    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(MfaVerificationFailed::class);

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
    }

    public function testConstructorPreservesArguments(): void
    {
        $identity = self::createStub(Authenticatable::class);
        $factor   = self::createStub(Factor::class);

        $event = new MfaVerificationFailed(
            identity: $identity,
            factor: $factor,
            driver: 'sms',
            reason: MfaVerificationFailureReason::CodeInvalid,
        );

        self::assertSame($identity, $event->identity);
        self::assertSame($factor, $event->factor);
        self::assertSame('sms', $event->driver);
        self::assertSame(MfaVerificationFailureReason::CodeInvalid, $event->reason);
    }

    public function testFactorMayBeNull(): void
    {
        $identity = self::createStub(Authenticatable::class);

        $event = new MfaVerificationFailed(
            identity: $identity,
            factor: null,
            driver: 'unknown',
            reason: MfaVerificationFailureReason::DriverUnknown,
        );

        self::assertNull($event->factor);
        self::assertSame(MfaVerificationFailureReason::DriverUnknown, $event->reason);
    }
}
