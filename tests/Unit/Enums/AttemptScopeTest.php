<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Unit tests for the `AttemptScope` enum: its stable values, which name the
 * scope of each stored throttle row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptScope::class)]
final class AttemptScopeTest extends TestCase
{
    /**
     * The scopes, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testScopesAreTheStableValues(): void
    {
        self::assertSame([
            'FACTOR'   => 'factor',
            'IDENTITY' => 'identity',
            'IP'       => 'ip',
        ], array_column(AttemptScope::cases(), 'value', 'name'));
    }
}
