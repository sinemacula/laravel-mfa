<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Support\IdentityType;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `IdentityType`: an Eloquent identity's type is its morph class, and
 * any other identity's its class name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityType::class)]
final class IdentityTypeTest extends TestCase
{
    /**
     * An Eloquent identity is recorded under its morph class, so a morph map is
     * honoured.
     *
     * @return void
     */
    public function testAnEloquentIdentityIsItsMorphClass(): void
    {
        self::assertSame(TestUser::class, IdentityType::of(new TestUser));

        Relation::morphMap(['person' => TestUser::class]);

        try {
            self::assertSame('person', IdentityType::of(new TestUser));
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * Any other identity is recorded under its class name.
     *
     * @return void
     */
    public function testAnyOtherIdentityIsItsClassName(): void
    {
        self::assertSame(NonEloquentIdentity::class, IdentityType::of(new NonEloquentIdentity('plain-1')));
    }
}
