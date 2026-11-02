<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Tests for `RecoveryCodeGeneration`: generated with its codes, or refused with
 * its reason, told apart by the reason and never by an empty payload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeGeneration::class)]
final class RecoveryCodeGenerationResultTest extends TestCase
{
    /**
     * A generated set holds its codes, and no reason.
     *
     * @return void
     */
    public function testGeneratedHoldsTheCodes(): void
    {
        $code       = new RevealedSecret('ABCDEFGHJKLM');
        $generation = RecoveryCodeGeneration::generated([$code]);

        self::assertTrue($generation->wasGenerated());
        self::assertSame([$code], $generation->codes);
        self::assertNull($generation->reason);
    }

    /**
     * A refused set holds its reason, and no codes.
     *
     * @return void
     */
    public function testRefusedHoldsTheReason(): void
    {
        $generation = RecoveryCodeGeneration::refused(FailureReason::NOT_FRESH);

        self::assertFalse($generation->wasGenerated());
        self::assertSame([], $generation->codes);
        self::assertSame(FailureReason::NOT_FRESH, $generation->reason);
    }

    /**
     * Whether a set was generated is the reason's absence, not the codes'.
     *
     * @return void
     */
    public function testAnEmptySetIsStillGenerated(): void
    {
        self::assertTrue(RecoveryCodeGeneration::generated([])->wasGenerated());
    }
}
