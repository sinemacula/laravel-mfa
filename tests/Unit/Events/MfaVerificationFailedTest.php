<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;

/**
 * Unit tests for the `MfaVerificationFailed` event DTO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaVerificationFailed::class)]
final class MfaVerificationFailedTest extends TestCase
{
    /**
     * Test is final readonly class.
     *
     * @return void
     */
    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(MfaVerificationFailed::class);

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

        $event = new MfaVerificationFailed(
            identity: $identity,
            factor  : $factor,
            driver  : 'sms',
            reason  : FailureReason::INVALID_CODE,
            detail  : 'The code did not match.',
        );

        self::assertSame($identity, $event->identity);
        self::assertSame($factor, $event->factor);
        self::assertSame('sms', $event->driver);
        self::assertSame(FailureReason::INVALID_CODE, $event->reason);
        self::assertSame('The code did not match.', $event->detail);
    }

    /**
     * Test factor may be null.
     *
     * @return void
     */
    public function testFactorMayBeNull(): void
    {
        $identity = self::createStub(Authenticatable::class);

        $event = new MfaVerificationFailed(
            identity: $identity,
            factor  : null,
            driver  : 'totp',
            reason  : FailureReason::NOT_CONFIRMED,
            detail  : 'The factor was never confirmed.',
        );

        self::assertNull($event->factor);
        self::assertSame(FailureReason::NOT_CONFIRMED, $event->reason);
    }
}
