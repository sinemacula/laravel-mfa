<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\Operation;

/**
 * Unit tests for the `Operation` enum: the names the package's own step-up
 * operations are configured and checked by, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Operation::class)]
final class OperationTest extends TestCase
{
    /**
     * The operations, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testOperationsAreTheStableNames(): void
    {
        self::assertSame([
            'ADD_FACTOR'              => 'mfa.add_factor',
            'REPLACE_FACTOR'          => 'mfa.replace_factor',
            'REMOVE_FACTOR'           => 'mfa.remove_factor',
            'GENERATE_RECOVERY_CODES' => 'mfa.generate_recovery_codes',
        ], array_column(Operation::cases(), 'value', 'name'));
    }
}
