<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Factors\UncastOwnerKeyFactor;
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

    /**
     * Not an owner differing only in case or padding.
     *
     * @return void
     */
    public function testOwnsOnlyAFactorStoredForExactlyTheOwner(): void
    {
        $factor = new Factor(['authenticatable_type' => 'user', 'authenticatable_id' => '7']);

        self::assertTrue(FactorOwnerColumns::owns($factor, 'user', '7'));
        self::assertFalse(FactorOwnerColumns::owns($factor, 'User', '7'));
        self::assertFalse(FactorOwnerColumns::owns($factor, 'user', '07'));
        self::assertFalse(FactorOwnerColumns::owns($factor, 'user', '8'));
    }

    /**
     * Read as a string, so an integer key owns as one; a key that is neither
     * owns nothing.
     *
     * @return void
     */
    public function testOwnsByAStringOrIntegerKey(): void
    {
        self::assertTrue(FactorOwnerColumns::owns(new UncastOwnerKeyFactor(['authenticatable_type' => 'user', 'authenticatable_id' => 7]), 'user', '7'));
        self::assertFalse(FactorOwnerColumns::owns(new UncastOwnerKeyFactor(['authenticatable_type' => 'user', 'authenticatable_id' => 7.0]), 'user', '7'));
        self::assertFalse(FactorOwnerColumns::owns(new UncastOwnerKeyFactor(['authenticatable_type' => 'user']), 'user', ''));
    }

    /**
     * @return void
     */
    public function testOwnsThroughTheColumnsTheModelNames(): void
    {
        $factor = (new RemappedOwnerFactor)->forceFill(['owner_type' => 'user', 'owner_id' => '7']);

        self::assertSame(['owner_type', 'owner_id'], FactorOwnerColumns::of($factor));
        self::assertTrue(FactorOwnerColumns::owns($factor, 'user', '7'));
    }
}
