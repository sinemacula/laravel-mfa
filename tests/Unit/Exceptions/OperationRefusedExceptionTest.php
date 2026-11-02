<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;

/**
 * Tests for `OperationRefusedException`: a refusal says who made it, and what a
 * seam may reach leaves it unmarked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationRefusedException::class)]
final class OperationRefusedExceptionTest extends TestCase
{
    /**
     * The public constructor is unmarked.
     *
     * @return void
     */
    public function testThePublicConstructorIsUnmarked(): void
    {
        $refusal = new OperationRefusedException(FailureReason::NOT_FOUND, 'Detail.');

        self::assertFalse($refusal->byPackage);
        self::assertSame(FailureReason::NOT_FOUND, $refusal->reason);
        self::assertSame('Detail.', $refusal->getMessage());
    }

    /**
     * The package's own factory is marked.
     *
     * @return void
     */
    public function testThePackagesFactoryIsMarked(): void
    {
        $refusal = OperationRefusedException::byPackage(FailureReason::NOT_FOUND, 'Detail.');

        self::assertTrue($refusal->byPackage);
        self::assertSame(FailureReason::NOT_FOUND, $refusal->reason);
        self::assertSame('Detail.', $refusal->getMessage());
    }

    /**
     * The public `unless()` throws unmarked, only when not allowed.
     *
     * @return void
     */
    public function testUnlessIsUnmarked(): void
    {
        $unless = static fn (bool $allowed) => OperationRefusedException::unless($allowed, FailureReason::NOT_FOUND, 'Detail.');

        $unless(true);

        try {
            $unless(false);

            self::fail('The refusal must be thrown.');
        } catch (OperationRefusedException $refusal) {
            self::assertFalse($refusal->byPackage);
            self::assertSame('Detail.', $refusal->getMessage());
        }
    }

    /**
     * The package's `byPackageUnless()` throws marked, only when not allowed.
     *
     * @return void
     */
    public function testByPackageUnlessIsMarked(): void
    {
        $unless = static fn (bool $allowed) => OperationRefusedException::byPackageUnless($allowed, FailureReason::NOT_FOUND, 'Detail.');

        $unless(true);

        try {
            $unless(false);

            self::fail('The refusal must be thrown.');
        } catch (OperationRefusedException $refusal) {
            self::assertTrue($refusal->byPackage);
            self::assertSame(FailureReason::NOT_FOUND, $refusal->reason);
            self::assertSame('Detail.', $refusal->getMessage());
        }
    }
}
