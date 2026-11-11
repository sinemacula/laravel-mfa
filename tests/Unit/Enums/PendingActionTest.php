<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\PendingAction;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingAction::class)]
final class PendingActionTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testPendingActionsAreTheStableValues(): void
    {
        self::assertSame([
            'LIST_FACTORS'                 => 'mfa.list_factors',
            'SEND_CODE'                    => 'mfa.send_code',
            'VERIFY'                       => 'mfa.verify',
            'START_BOOTSTRAP_ENROLLMENT'   => 'mfa.start_bootstrap_enrollment',
            'CONFIRM_BOOTSTRAP_ENROLLMENT' => 'mfa.confirm_bootstrap_enrollment',
        ], array_column(PendingAction::cases(), 'value', 'name'));
    }
}
