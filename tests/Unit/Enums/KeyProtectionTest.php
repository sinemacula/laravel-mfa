<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyProtection::class)]
final class KeyProtectionTest extends TestCase
{
    /**
     * Pinned so a rename fails.
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
