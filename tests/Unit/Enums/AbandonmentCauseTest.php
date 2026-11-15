<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AbandonmentCause;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbandonmentCause::class)]
final class AbandonmentCauseTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testAbandonmentCausesAreTheStableValues(): void
    {
        self::assertSame([
            'RESTARTED'          => 'restarted',
            'CANCELED'           => 'canceled',
            'ATTEMPTS_EXHAUSTED' => 'attempts_exhausted',
            'RESET'              => 'reset',
        ], array_column(AbandonmentCause::cases(), 'value', 'name'));
    }
}
