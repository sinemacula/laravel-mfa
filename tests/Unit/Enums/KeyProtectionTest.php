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
     * The key protections, in order, with their stable values.
     *
     * @return void
     */
    public function testKeyProtectionsAreTheStableValues(): void
    {
        self::assertSame([
            'hardware',
            'software',
        ], array_map(static fn (KeyProtection $protection): string => $protection->value, KeyProtection::cases()));
    }
}
