<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Purpose::class)]
final class PurposeTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testPurposesAreTheStableValues(): void
    {
        self::assertSame([
            'SIGN_IN'        => 'sign_in',
            'REAUTHENTICATE' => 'reauthenticate',
            'STEP_UP'        => 'step_up',
            'ENROLLMENT'     => 'enrollment',
        ], array_column(Purpose::cases(), 'value', 'name'));
    }
}
