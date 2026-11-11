<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementMode::class)]
final class RequirementModeTest extends TestCase
{
    /**
     * Pinned so a rename fails.
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
