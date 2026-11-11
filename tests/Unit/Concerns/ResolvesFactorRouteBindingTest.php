<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Factors\FactorRouteBinding;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\DecodedRouteKeyFactor;
use Tests\Fixtures\Factors\OrderedRouteKeyFactor;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Factors\SoftDeletingFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRouteBinding::class)]
#[CoversTrait(ResolvesFactorRouteBinding::class)]
final class ResolvesFactorRouteBindingTest extends TestCase
{
    /**
     * @return void
     */
    public function testBindsTheCallersOwnFactor(): void
    {
        $user   = $this->signedInUser();
        $factor = $this->factorOf($user);
        $bound  = (new Factor)->resolveRouteBinding($factor->id);

        self::assertInstanceOf(Factor::class, $bound);
        self::assertSame($factor->id, $bound->id);
        self::assertNotSame($factor, $bound);
    }

    /**
     * By owner key and by owner type, exactly as an id that does not exist.
     *
     * @return void
     */
    public function testAnotherIdentitysFactorMisses(): void
    {
        $user  = $this->signedInUser();
        $other = TestUser::query()->create(['email' => 'other@example.test']);

        self::assertNull((new Factor)->resolveRouteBinding($this->factorOf($other)->id));
        self::assertNull((new Factor)->resolveRouteBinding($this->factor(NonEloquentIdentity::class, (string) $user->id)->id));
        self::assertNull((new Factor)->resolveRouteBinding('01JUNKNOWNFACTOR0000000000'));
    }

    /**
     * @return void
     */
    public function testNoCallerMissesWithNoQuery(): void
    {
        $factor = $this->factorOf(TestUser::query()->create(['email' => 'owner@example.test']));

        DB::enableQueryLog();

        self::assertNull((new Factor)->resolveRouteBinding($factor->id));
        self::assertSame([], DB::getQueryLog());
    }

    /**
     * Its own factor included, with no query.
     *
     * @return void
     */
    public function testAMachineIdentityMisses(): void
    {
        $identity = new NonEloquentIdentity('machine-1', person: false);
        $factor   = $this->factor(NonEloquentIdentity::class, 'machine-1');

        $this->actingAs($identity);

        DB::enableQueryLog();

        self::assertNull((new Factor)->resolveRouteBinding($factor->id));
        self::assertSame([], DB::getQueryLog());
    }

    /**
     * @return void
     */
    public function testTheBoundSubjectTypeResolverDecidesWhoIsAPerson(): void
    {
        $user   = $this->signedInUser();
        $factor = $this->factorOf($user);

        $resolver = \Mockery::mock(SubjectTypeResolver::class);
        $resolver->shouldReceive('isPerson')->with($user)->andReturnFalse();

        $this->container()->instance(SubjectTypeResolver::class, $resolver);

        self::assertNull((new Factor)->resolveRouteBinding($factor->id));

        \Mockery::close();
    }

    /**
     * And does not fail the binding.
     *
     * @return void
     */
    public function testAnIdentityWithAKeyOfAnotherShapeOwnsNothing(): void
    {
        $identity = new NonEloquentIdentity(['nested' => 'array']);
        $factor   = $this->factor(NonEloquentIdentity::class, 'plain-1');

        $this->actingAs($identity);

        self::assertNull((new Factor)->resolveRouteBinding($factor->id));
    }

    /**
     * The row the parent's lookup finds is still held to the caller.
     *
     * @return void
     */
    public function testACustomKeyIsLookedUpThroughTheField(): void
    {
        $user   = $this->signedInUser();
        $factor = $this->factorOf($user, ['label' => 'Work phone']);

        self::assertSame($factor->id, (new Factor)->resolveRouteBinding('Work phone', 'label')?->getKey());
        self::assertNull((new Factor)->resolveRouteBinding('Home phone', 'label'));
    }

    /**
     * The fixture orders the lookup by primary key, so the other identity's row
     * is first on every database.
     *
     * @return void
     */
    public function testADuplicateCustomKeyFailsClosed(): void
    {
        $user  = $this->signedInUser();
        $other = TestUser::query()->create(['email' => 'other@example.test']);

        $theirs = $this->factorOf($other, ['id' => '01JAAAAAAAAAAAAAAAAAAAAAAA', 'label' => 'Phone']);
        $this->factorOf($user, ['id' => '01JBBBBBBBBBBBBBBBBBBBBBBB', 'label' => 'Phone']);

        $firstFound = (new OrderedRouteKeyFactor)->resolveRouteBindingQuery(new OrderedRouteKeyFactor, 'Phone', 'label')->first();

        self::assertInstanceOf(OrderedRouteKeyFactor::class, $firstFound);
        self::assertSame($theirs->id, $firstFound->getKey());
        self::assertNull((new OrderedRouteKeyFactor)->resolveRouteBinding('Phone', 'label'));
    }

    /**
     * Rather than as the exception the shipped model's lookup throws.
     *
     * @return void
     */
    public function testAMalformedUniqueIdMisses(): void
    {
        $this->signedInUser();

        self::assertNull((new Factor)->resolveRouteBinding('not-a-ulid'));
    }

    /**
     * The URL value is decoded there, and what it finds is held to the caller.
     *
     * @return void
     */
    public function testABaseModelsOwnBindingIsTheLookup(): void
    {
        $user   = $this->signedInUser();
        $factor = $this->factorOf($user);
        $other  = $this->factorOf(TestUser::query()->create(['email' => 'other@example.test']));

        self::assertSame($factor->id, (new DecodedRouteKeyFactor)->resolveRouteBinding(base64_encode($factor->id))?->getKey());
        self::assertNull((new DecodedRouteKeyFactor)->resolveRouteBinding($factor->id));
        self::assertNull((new DecodedRouteKeyFactor)->resolveRouteBinding(base64_encode($other->id)));
    }

    /**
     * Whoever it belongs to.
     *
     * @return void
     */
    public function testAModelOfAnotherClassMisses(): void
    {
        $this->signedInUser();

        self::assertNull((new DecodedRouteKeyFactor)->resolveRouteBinding(DecodedRouteKeyFactor::STRANGER));
    }

    /**
     * It finds the caller's soft-deleted factor, the ordinary lookup does not;
     * another identity's misses either way.
     *
     * @return void
     */
    public function testTheSoftDeletableLookupIsHeldToTheCallerToo(): void
    {
        Schema::table(TableNames::of(TableNames::FACTORS), static function (Blueprint $table): void {
            $table->softDeletes();
        });

        $user = $this->signedInUser();

        $factor = $this->softDeletedFactor($user);
        $other  = $this->softDeletedFactor(TestUser::query()->create(['email' => 'other@example.test']));

        self::assertSame($factor->id, (new SoftDeletingFactor)->resolveSoftDeletableRouteBinding($factor->id)?->getKey());
        self::assertNull((new SoftDeletingFactor)->resolveRouteBinding($factor->id));
        self::assertNull((new SoftDeletingFactor)->resolveSoftDeletableRouteBinding($other->id));
    }

    /**
     * @return void
     */
    public function testRemappedOwnerColumnsAreRead(): void
    {
        Schema::table(TableNames::of(TableNames::FACTORS), static function (Blueprint $table): void {
            $table->string('owner_type')->nullable();
            $table->string('owner_id')->nullable();
        });

        $user = $this->signedInUser();

        $mine   = $this->factor('unused', 'unused', ['owner_type' => $user->getMorphClass(), 'owner_id' => (string) $user->id]);
        $theirs = $this->factor($user->getMorphClass(), (string) $user->id, ['owner_type' => $user->getMorphClass(), 'owner_id' => 'someone-else']);

        self::assertSame($mine->id, (new RemappedOwnerFactor)->resolveRouteBinding($mine->id)?->getKey());
        self::assertNull((new RemappedOwnerFactor)->resolveRouteBinding($theirs->id));
    }

    /**
     * As a case-insensitive collation would have it.
     *
     * @return void
     */
    public function testAnOwnerDifferingOnlyInCaseMisses(): void
    {
        $this->actingAs(new NonEloquentIdentity('plain-a'));

        $key  = $this->factor(NonEloquentIdentity::class, 'PLAIN-A');
        $type = $this->factor(strtolower(NonEloquentIdentity::class), 'plain-a');
        $mine = $this->factor(NonEloquentIdentity::class, 'plain-a');

        self::assertNull((new Factor)->resolveRouteBinding($key->id));
        self::assertNull((new Factor)->resolveRouteBinding($type->id));
        self::assertSame($mine->id, (new Factor)->resolveRouteBinding($mine->id)?->getKey());
    }

    /**
     * As the string it is stored as.
     *
     * @return void
     */
    public function testAnIntegerOwnerKeyIsTheOwners(): void
    {
        $factor = $this->factor(NonEloquentIdentity::class, '7');

        $this->actingAs(new NonEloquentIdentity(7));

        self::assertSame($factor->id, (new Factor)->resolveRouteBinding($factor->id)?->getKey());
    }

    /**
     * A failing query is not a miss.
     *
     * @return void
     */
    public function testADatabaseFailurePropagates(): void
    {
        $factor = $this->factorOf($this->signedInUser());

        Schema::drop(TableNames::of(TableNames::FACTORS));

        $this->expectException(QueryException::class);

        try {
            (new Factor)->resolveRouteBinding($factor->id);
        } finally {
            Schema::create(TableNames::of(TableNames::FACTORS), static function (Blueprint $table): void {
                $table->ulid('id')->primary();
            });
        }
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signedInUser(): TestUser
    {
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        $this->actingAs($user);

        return $user;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorOf(TestUser $user, array $attributes = []): Factor
    {
        return $this->factor($user->getMorphClass(), (string) $user->id, $attributes);
    }

    /**
     * @param  string  $type
     * @param  string  $key
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factor(string $type, string $key, array $attributes = []): Factor
    {
        $factor = new Factor;

        $factor->forceFill([
            'authenticatable_type' => $type,
            'authenticatable_id'   => $key,
            'type'                 => 'totp',
            ...$attributes,
        ])->save();

        return $factor;
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \Tests\Fixtures\Factors\SoftDeletingFactor
     */
    private function softDeletedFactor(TestUser $user): SoftDeletingFactor
    {
        /** @var \Tests\Fixtures\Factors\SoftDeletingFactor $factor */
        $factor = SoftDeletingFactor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
        ]);

        $factor->delete();

        return $factor;
    }
}
