<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use Tests\Fixtures\NonEloquentIdentity;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `CurrentIdentity`: which authenticated identity the services act
 * for, and the type it is recorded under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CurrentIdentity::class)]
final class CurrentIdentityTest extends TestCase
{
    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * A guest has no current identity.
     *
     * @return void
     */
    public function testResolvesNothingForAGuest(): void
    {
        self::assertNull(CurrentIdentity::resolve());
    }

    /**
     * An authenticated MFA-capable identity is the current identity.
     *
     * @return void
     */
    public function testResolvesTheAuthenticatedMfaCapableIdentity(): void
    {
        $user = TestUser::query()->create(['email' => 'current@example.com']);

        $this->actingAs($user);

        self::assertSame($user, CurrentIdentity::resolve());
    }

    /**
     * An authenticated identity that is not MFA-capable is no current identity.
     *
     * @return void
     */
    public function testResolvesNothingForAnIdentityThatIsNotMfaCapable(): void
    {
        $this->actingAs(new GenericUser(['id' => 1]));

        self::assertNull(CurrentIdentity::resolve());
    }

    /**
     * An Eloquent identity is recorded under its morph class, so the
     * application's morph map is honoured.
     *
     * @return void
     */
    public function testTypeOfAnEloquentIdentityIsItsMorphClass(): void
    {
        Relation::morphMap(['test-user' => TestUser::class]);

        self::assertSame('test-user', CurrentIdentity::typeOf(new TestUser));
    }

    /**
     * A non-Eloquent identity is recorded under its class name.
     *
     * @return void
     */
    public function testTypeOfANonEloquentIdentityIsItsClass(): void
    {
        self::assertSame(NonEloquentIdentity::class, CurrentIdentity::typeOf(new NonEloquentIdentity));
    }
}
