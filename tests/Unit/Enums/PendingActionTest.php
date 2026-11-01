<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\PendingAction;

/**
 * Unit tests for the `PendingAction` enum: the actions a pending session may
 * allow, with the values authentication adopts, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingAction::class)]
final class PendingActionTest extends TestCase
{
    /**
     * The pending actions, in order, with their stable values.
     *
     * @return void
     */
    public function testPendingActionsAreTheStableValues(): void
    {
        self::assertSame([
            'mfa.list_factors',
            'mfa.send_code',
            'mfa.verify',
            'mfa.start_bootstrap_enrollment',
            'mfa.confirm_bootstrap_enrollment',
        ], array_map(static fn (PendingAction $action): string => $action->value, PendingAction::cases()));
    }
}
