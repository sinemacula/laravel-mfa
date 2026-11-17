<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoActiveTenant::class)]
final class NoActiveTenantTest extends TestCase
{
    /**
     * @return void
     */
    public function testNamesNoTenant(): void
    {
        self::assertNull((new NoActiveTenant)->activeTenant(new NonEloquentIdentity('ext-1'), 'web'));
    }
}
