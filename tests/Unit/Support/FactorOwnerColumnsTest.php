<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorOwnerColumns::class)]
final class FactorOwnerColumnsTest extends TestCase
{
    /**
     * @return void
     */
    public function testNamesTheOwnerColumnsOfABlankFactor(): void
    {
        self::assertSame(['authenticatable_type', 'authenticatable_id'], FactorOwnerColumns::of(new Factor));
    }

    /**
     * The owner here is not an Eloquent model.
     *
     * @return void
     */
    public function testNamesTheOwnerColumnsWithoutBuildingTheOwner(): void
    {
        $factor = new Factor([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-1',
            'type'                 => 'totp',
        ]);

        self::assertSame(['authenticatable_type', 'authenticatable_id'], FactorOwnerColumns::of($factor));
        self::assertFalse($factor->relationLoaded('authenticatable'));
        self::assertSame(NonEloquentIdentity::class, $factor->getAttribute('authenticatable_type'));
    }
}
