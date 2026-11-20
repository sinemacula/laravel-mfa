<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Concerns\HashesOwner;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\RecoveryCodes\CustomRecoveryCode;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HashesOwner::class)]
final class HashesOwnerTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return void
     */
    public function testNamesTheOwnerRelationAndHashColumn(): void
    {
        $factor = new Factor;

        self::assertInstanceOf(MorphTo::class, $factor->authenticatable());
        self::assertSame('authenticatable_type', $factor->authenticatable()->getMorphType());
        self::assertSame('owner_hash', $factor->getOwnerHashName());
    }

    /**
     * The type names no model, so the owner is never built.
     *
     * @return void
     */
    public function testEverySaveStoresTheOwnersHash(): void
    {
        $factor = Factor::query()->create(['authenticatable_type' => 'users', 'authenticatable_id' => 'ab12Cd', 'type' => 'totp']);

        self::assertSame((new ProofOwner('users', 'ab12Cd'))->hash(), Factor::query()->toBase()->value('owner_hash'));

        $factor->update(['authenticatable_id' => 'AB12CD']);

        self::assertSame((new ProofOwner('users', 'AB12CD'))->hash(), Factor::query()->toBase()->value('owner_hash'));
    }

    /**
     * @return void
     */
    public function testAnIntegerKeyIsHashedAsAStringInTheModelsOwnColumns(): void
    {
        $code = new CustomRecoveryCode;

        $code->forceFill(['owner_type' => 'users', 'owner_id' => 42, 'hash' => 'hash', 'set_number' => 1])->save();

        self::assertSame((new ProofOwner('users', '42'))->hash(), CustomRecoveryCode::query()->toBase()->value('owner_digest'));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function partialOwners(): iterable
    {
        yield 'no type' => [['authenticatable_id' => '42']];
        yield 'no key' => [['authenticatable_type' => 'users']];
    }

    /**
     * The column refuses the row rather than storing a hash of half an owner.
     *
     * @param  array<string, string>  $owner
     * @return void
     */
    #[DataProvider('partialOwners')]
    public function testAPartialOwnerIsNotHashed(array $owner): void
    {
        $state = new IdentityState($owner);

        $this->assertThrows(static fn () => $state->save(), QueryException::class);

        self::assertNull($state->getAttribute('owner_hash'));
    }
}
