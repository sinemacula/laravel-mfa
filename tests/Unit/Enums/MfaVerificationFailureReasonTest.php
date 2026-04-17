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
    /**
     * Test is backed by string.
     *
     * @return void
     */
    public function testIsBackedByString(): void
    {
        $reflection = new \ReflectionEnum(MfaVerificationFailureReason::class);

        self::assertTrue($reflection->isBacked());
        self::assertSame('string', (string) $reflection->getBackingType());
    }

    /**
     * Test factor locked case value.
     *
     * @return void
     */
    public function testFactorLockedCaseValue(): void
    {
        self::assertSame('factor_locked', MfaVerificationFailureReason::FACTOR_LOCKED->value);
    }

    /**
     * Test code invalid case value.
     *
     * @return void
     */
    public function testCodeInvalidCaseValue(): void
    {
        self::assertSame('code_invalid', MfaVerificationFailureReason::CODE_INVALID->value);
    }

    /**
     * Test code expired case value.
     *
     * @return void
     */
    public function testCodeExpiredCaseValue(): void
    {
        self::assertSame('code_expired', MfaVerificationFailureReason::CODE_EXPIRED->value);
    }

    /**
     * Test code missing case value.
     *
     * @return void
     */
    public function testCodeMissingCaseValue(): void
    {
        self::assertSame('code_missing', MfaVerificationFailureReason::CODE_MISSING->value);
    }

    /**
     * Test secret missing case value.
     *
     * @return void
     */
    public function testSecretMissingCaseValue(): void
    {
        self::assertSame('secret_missing', MfaVerificationFailureReason::SECRET_MISSING->value);
    }

    /**
     * Test driver unknown case value.
     *
     * @return void
     */
    public function testDriverUnknownCaseValue(): void
    {
        self::assertSame('driver_unknown', MfaVerificationFailureReason::DRIVER_UNKNOWN->value);
    }

    /**
     * Test identity unsupported case value.
     *
     * @return void
     */
    public function testIdentityUnsupportedCaseValue(): void
    {
        self::assertSame('identity_unsupported', MfaVerificationFailureReason::IDENTITY_UNSUPPORTED->value);
    }

    /**
     * Test exposes all seven cases.
     *
     * @return void
     */
    public function testExposesAllSevenCases(): void
    {
        self::assertCount(7, MfaVerificationFailureReason::cases());
    }
}
