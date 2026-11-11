<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorStatus::class)]
final class FactorStatusTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testStatusesAreTheStableValues(): void
    {
        self::assertSame([
            'PENDING'   => 'pending',
            'CONFIRMED' => 'confirmed',
        ], array_column(FactorStatus::cases(), 'value', 'name'));
    }
}
