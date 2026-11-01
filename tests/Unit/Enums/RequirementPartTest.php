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
     * The parts, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testPartsAreTheStableValues(): void
    {
        self::assertSame([
            'ADDITIONAL_VERIFICATION' => 'additional_verification',
            'MULTIFACTOR'             => 'multifactor',
            'MINIMUM_LEVEL'           => 'minimum_level',
            'PHISHING_RESISTANCE'     => 'phishing_resistance',
        ], array_column(RequirementPart::cases(), 'value', 'name'));
    }
}
