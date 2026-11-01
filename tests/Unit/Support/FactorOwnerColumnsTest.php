<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;

/**
 * Unit tests for `FactorOwnerColumns`: a factor's owner columns, read without
 * building its owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorOwnerColumns::class)]
final class FactorOwnerColumnsTest extends TestCase
{
    /**
     * A blank factor names its owner's type column and key column.
     *
     * @return void
     */
    public function testNamesTheOwnerColumnsOfABlankFactor(): void
    {
        self::assertSame(['authenticatable_type', 'authenticatable_id'], FactorOwnerColumns::of(new Factor));
    }

    /**
     * A factor owned by an identity that is not an Eloquent model names the
     * same columns, and its owner is never built or loaded.
     *
     * @return void
     */
    public function testNamesTheOwnerColumnsWithoutBuildingTheOwner(): void
    {
        $factor = new Factor([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-1',
            'driver'               => 'totp',
        ]);

        self::assertSame(['authenticatable_type', 'authenticatable_id'], FactorOwnerColumns::of($factor));
        self::assertFalse($factor->relationLoaded('authenticatable'));
        self::assertSame(NonEloquentIdentity::class, $factor->getAttribute('authenticatable_type'));
    }
}
