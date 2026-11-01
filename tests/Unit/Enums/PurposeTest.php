<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Unit tests for the `Purpose` enum, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Purpose::class)]
final class PurposeTest extends TestCase
{
    /**
     * The purposes, in order, with their stable values.
     *
     * @return void
     */
    public function testPurposesAreTheStableValues(): void
    {
        self::assertSame([
            'sign_in',
            'reauthenticate',
            'step_up',
            'enrollment',
        ], array_map(static fn (Purpose $purpose): string => $purpose->value, Purpose::cases()));
    }
}
