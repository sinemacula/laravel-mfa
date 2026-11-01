<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `ProofOwner`: an identity is recorded by its morph class or class
 * name and its key as a string, a binding names its owner, and two owners
 * never share a slot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofOwner::class)]
final class ProofOwnerTest extends TestCase
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
     * An Eloquent identity is recorded by its morph class and its integer key
     * as a string.
     *
     * @return void
     */
    public function testRecordsAnEloquentIdentityByItsMorphClass(): void
    {
        Relation::morphMap(['user' => TestUser::class], false);

        $user = new TestUser;

        $user->setAttribute('id', 7);

        $owner = ProofOwner::of($user);

        self::assertSame('user', $owner->type);
        self::assertSame('7', $owner->key);
    }

    /**
     * An identity that is not an Eloquent model is recorded by its class name.
     *
     * @return void
     */
    public function testRecordsAnotherIdentityByItsClassName(): void
    {
        $owner = ProofOwner::of(new NonEloquentIdentity('ext-1'));

        self::assertSame(NonEloquentIdentity::class, $owner->type);
        self::assertSame('ext-1', $owner->key);
    }

    /**
     * The keys that cannot name an owner.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function unsupportedKeys(): iterable
    {
        yield 'an empty string' => ['', 'string'];
        yield 'null' => [null, 'null'];
        yield 'an object' => [new \stdClass, \stdClass::class];
        yield 'a float' => [1.5, 'float'];
    }

    /**
     * A key that is neither a non-empty string nor an integer is refused,
     * naming its type.
     *
     * @param  mixed  $key
     * @param  string  $type
     * @return void
     */
    #[DataProvider('unsupportedKeys')]
    public function testRefusesAKeyThatCannotNameAnOwner(mixed $key, string $type): void
    {
        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage(sprintf('An identity\'s key must be a non-empty string or an integer to hold proofs; got [%s].', $type));

        ProofOwner::of(new NonEloquentIdentity($key));
    }

    /**
     * The owner a binding names is its identity type and key, and owns that
     * binding but none naming another type or key.
     *
     * @return void
     */
    public function testOwnsOnlyTheBindingsThatNameIt(): void
    {
        $binding = new ProofBinding('user', '7', 'web', 'sign-in-1', Purpose::STEP_UP);
        $owner   = ProofOwner::boundBy($binding);

        self::assertSame('user', $owner->type);
        self::assertSame('7', $owner->key);
        self::assertTrue($owner->owns($binding));
        self::assertFalse($owner->owns(new ProofBinding('admin', '7', 'web', 'sign-in-1', Purpose::STEP_UP)));
        self::assertFalse($owner->owns(new ProofBinding('user', '8', 'web', 'sign-in-1', Purpose::STEP_UP)));
    }

    /**
     * The slot carries the type's length, so a separator inside the type or
     * the key never makes two owners share one.
     *
     * @return void
     */
    public function testTheSlotNeverMakesTwoOwnersMeet(): void
    {
        self::assertSame('4:user|7', (new ProofOwner('user', '7'))->slot());
        self::assertNotSame((new ProofOwner('a|b', 'c'))->slot(), (new ProofOwner('a', 'b|c'))->slot());
    }
}
