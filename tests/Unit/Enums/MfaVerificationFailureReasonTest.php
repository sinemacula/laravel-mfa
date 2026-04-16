<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;

/**
 * Unit tests for the `MfaVerificationFailureReason` enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaVerificationFailureReasonTest extends TestCase
{
    public function testIsBackedByString(): void
    {
        $reflection = new \ReflectionEnum(MfaVerificationFailureReason::class);

        self::assertTrue($reflection->isBacked());
        self::assertSame('string', (string) $reflection->getBackingType());
    }

    public function testFactorLockedCaseValue(): void
    {
        self::assertSame('factor_locked', MfaVerificationFailureReason::FactorLocked->value);
    }

    public function testCodeInvalidCaseValue(): void
    {
        self::assertSame('code_invalid', MfaVerificationFailureReason::CodeInvalid->value);
    }

    public function testCodeExpiredCaseValue(): void
    {
        self::assertSame('code_expired', MfaVerificationFailureReason::CodeExpired->value);
    }

    public function testCodeMissingCaseValue(): void
    {
        self::assertSame('code_missing', MfaVerificationFailureReason::CodeMissing->value);
    }

    public function testSecretMissingCaseValue(): void
    {
        self::assertSame('secret_missing', MfaVerificationFailureReason::SecretMissing->value);
    }

    public function testDriverUnknownCaseValue(): void
    {
        self::assertSame('driver_unknown', MfaVerificationFailureReason::DriverUnknown->value);
    }

    public function testIdentityUnsupportedCaseValue(): void
    {
        self::assertSame('identity_unsupported', MfaVerificationFailureReason::IdentityUnsupported->value);
    }

    public function testExposesAllSevenCases(): void
    {
        self::assertCount(7, MfaVerificationFailureReason::cases());
    }
}
