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
     * The operations, in order, with their stable names.
     *
     * @return void
     */
    public function testOperationsAreTheStableNames(): void
    {
        self::assertSame([
            'mfa.add_factor',
            'mfa.replace_factor',
            'mfa.remove_factor',
            'mfa.generate_recovery_codes',
        ], array_map(static fn (Operation $operation): string => $operation->value, Operation::cases()));
    }
}
