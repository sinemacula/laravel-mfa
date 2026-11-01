<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Unit tests for the `FailureReason` enum: the values listeners and
 * applications count and word, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureReason::class)]
final class FailureReasonTest extends TestCase
{
    /**
     * The failure reasons, in order, with their stable values.
     *
     * @return void
     */
    public function testFailureReasonsAreTheReportedValues(): void
    {
        self::assertSame([
            'invalid_code',
            'expired',
            'replayed',
            'locked',
            'not_confirmed',
            'not_accepted',
            'type_not_enabled',
            'no_factor',
            'not_found',
            'sending_capped',
            'mfa_enrollment_required',
            'identity_inactive',
            'machine_identity',
        ], array_map(static fn (FailureReason $reason): string => $reason->value, FailureReason::cases()));
    }
}
