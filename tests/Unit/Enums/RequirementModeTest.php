<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;

/**
 * Unit tests for the `RequirementMode` enum: the values an application's
 * `requirement` setting takes, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementMode::class)]
final class RequirementModeTest extends TestCase
{
    /**
     * The modes, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testModesAreTheStableValues(): void
    {
        self::assertSame([
            'NEVER'    => 'never',
            'ENROLLED' => 'enrolled',
            'ALWAYS'   => 'always',
        ], array_column(RequirementMode::cases(), 'value', 'name'));
    }
}
