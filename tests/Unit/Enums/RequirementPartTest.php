<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;

/**
 * Unit tests for the `RequirementPart` enum: the codes that name what a
 * requirement asks for, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementPart::class)]
final class RequirementPartTest extends TestCase
{
    /**
     * The parts, in order, with their stable values.
     *
     * @return void
     */
    public function testPartsAreTheStableValues(): void
    {
        self::assertSame([
            'additional_verification',
            'multifactor',
            'minimum_level',
            'phishing_resistance',
        ], array_map(static fn (RequirementPart $part): string => $part->value, RequirementPart::cases()));
    }
}
