<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;

/**
 * Unit tests for the `KeyProtection` enum, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyProtection::class)]
final class KeyProtectionTest extends TestCase
{
    /**
     * The key protections, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testKeyProtectionsAreTheStableValues(): void
    {
        self::assertSame([
            'HARDWARE' => 'hardware',
            'SOFTWARE' => 'software',
        ], array_column(KeyProtection::cases(), 'value', 'name'));
    }
}
