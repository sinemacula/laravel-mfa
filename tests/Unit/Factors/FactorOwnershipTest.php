<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\NonEloquentIdentity;
use Tests\Fixtures\NonScalarIdentifierUser;
use Tests\Fixtures\SecondaryUser;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `FactorOwnership`: a factor belongs to an identity only when its
 * owner's type and identifier both match, under the safe-cast identifier rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorOwnership::class)]
final class FactorOwnershipTest extends TestCase
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
     * Stored identifiers that name identity 1.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function matchingIdentifiers(): iterable
    {
        yield 'integer' => [1];
        yield 'string' => ['1'];
    }

    /**
     * An Eloquent factor belongs to the identity named by its owner columns,
     * whether the identifier is stored as an integer or a string.
     *
     * @param  mixed  $storedId
     * @return void
     */
    #[DataProvider('matchingIdentifiers')]
    public function testAnEloquentFactorBelongsToTheIdentityItsColumnsName(mixed $storedId): void
    {
        $this->expectNotToPerformAssertions();

        FactorOwnership::assert($this->eloquentFactor(TestUser::class, $storedId), $this->user(1));
    }

    /**
     * An Eloquent factor recorded under a morph alias belongs to the identity
     * the alias maps to.
     *
     * @return void
     */
    public function testAnEloquentFactorMatchesThroughTheMorphMap(): void
    {
        Relation::morphMap(['test-user' => TestUser::class]);

        $this->expectNotToPerformAssertions();

        FactorOwnership::assert($this->eloquentFactor('test-user', 1), $this->user(1));
    }

    /**
     * Owner columns that do not name identity 1 of `TestUser`.
     *
     * @return iterable<string, array{string, mixed}>
     */
    public static function foreignOwners(): iterable
    {
        yield 'another type' => [SecondaryUser::class, 1];
        yield 'another identifier' => [TestUser::class, 2];
        yield 'no identifier' => [TestUser::class, null];
    }

    /**
     * An Eloquent factor whose columns name another identity, or no identifier
     * the safe-cast rule accepts, does not belong to the identity.
     *
     * @param  string  $storedType
     * @param  mixed  $storedId
     * @return void
     */
    #[DataProvider('foreignOwners')]
    public function testAnEloquentFactorOfAnotherOwnerIsRefused(string $storedType, mixed $storedId): void
    {
        $this->expectException(FactorOwnershipMismatchException::class);

        FactorOwnership::assert($this->eloquentFactor($storedType, $storedId), $this->user(1));
    }

    /**
     * An Eloquent factor is refused for an identity whose identifier the
     * safe-cast rule does not accept.
     *
     * @return void
     */
    public function testAnEloquentFactorIsRefusedForANonScalarIdentity(): void
    {
        $this->expectException(FactorOwnershipMismatchException::class);

        FactorOwnership::assert($this->eloquentFactor(NonScalarIdentifierUser::class, 1), new NonScalarIdentifierUser);
    }

    /**
     * A non-Eloquent factor belongs to the identity it reports as its owner.
     *
     * @param  mixed  $ownerId
     * @return void
     */
    #[DataProvider('matchingIdentifiers')]
    public function testANonEloquentFactorBelongsToItsReportedOwner(mixed $ownerId): void
    {
        $this->expectNotToPerformAssertions();

        FactorOwnership::assert(new InMemoryFactor(authenticatable: new NonEloquentIdentity($ownerId)), new NonEloquentIdentity(1));
    }

    /**
     * Reported owners that do not match the identity.
     *
     * @return iterable<string, array{?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable}>
     */
    public static function foreignReportedOwners(): iterable
    {
        $user = new TestUser;

        $user->setAttribute('id', 1);

        yield 'no owner' => [null, new NonEloquentIdentity(1)];
        yield 'another class' => [$user, new NonEloquentIdentity(1)];
        yield 'another identifier' => [new NonEloquentIdentity(2), new NonEloquentIdentity(1)];
        yield 'a float owner identifier' => [new NonEloquentIdentity(1.0), new NonEloquentIdentity(1)];
        yield 'a float identity identifier' => [new NonEloquentIdentity(1), new NonEloquentIdentity(1.0)];
        yield 'a missing identifier on both' => [new NonEloquentIdentity(null), new NonEloquentIdentity(null)];
    }

    /**
     * A non-Eloquent factor with no owner, an owner of another class or
     * identifier, or an identifier the safe-cast rule does not accept, does not
     * belong to the identity.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $owner
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    #[DataProvider('foreignReportedOwners')]
    public function testANonEloquentFactorOfAnotherOwnerIsRefused(?MultiFactorAuthenticatable $owner, MultiFactorAuthenticatable $identity): void
    {
        $this->expectException(FactorOwnershipMismatchException::class);

        FactorOwnership::assert(new InMemoryFactor(authenticatable: $owner), $identity);
    }

    /**
     * Build an unsaved factor whose owner columns hold the given values.
     *
     * @param  string  $type
     * @param  mixed  $id
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function eloquentFactor(string $type, mixed $id): Factor
    {
        $factor = new Factor;

        $factor->setAttribute('driver', 'totp');
        $factor->setAttribute('authenticatable_type', $type);
        $factor->setAttribute('authenticatable_id', $id);

        return $factor;
    }

    /**
     * Build an unsaved test user with the given identifier.
     *
     * @param  int  $id
     * @return \Tests\Fixtures\TestUser
     */
    private function user(int $id): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', $id);

        return $user;
    }
}
