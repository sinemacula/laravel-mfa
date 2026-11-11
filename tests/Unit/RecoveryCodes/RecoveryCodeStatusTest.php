<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeStatus::class)]
final class RecoveryCodeStatusTest extends TestCase
{
    /**
     * Used up or not.
     *
     * @return void
     */
    public function testASetExistsWhenItHasATime(): void
    {
        $at     = CarbonImmutable::parse('2026-11-01 08:00:00');
        $status = new RecoveryCodeStatus(0, 3, $at);

        self::assertSame(0, $status->remaining);
        self::assertSame(3, $status->generation);
        self::assertSame($at, $status->generatedAt);
        self::assertTrue($status->exists());
        self::assertFalse((new RecoveryCodeStatus(0, 3, null))->exists());
    }
}
