<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\TestCase;

/**
 * Tests for `FactorRemoval`, the removal every entry point shares: it runs only
 * inside the identity's factor state transaction, and removes a factor by its
 * id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRemoval::class)]
final class FactorRemovalTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * A removal outside a transaction is refused, and removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalOutsideATransactionIsRefused(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        try {
            $this->removal()->remove($user, self::APPLICATION, $factor, new Collection([$factor]));
            self::fail('A removal outside a transaction was expected to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A factor is removed only inside the identity\'s factor state transaction.', $exception->getMessage());
        }

        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * A factor with no id is not removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorWithNoIdIsRefused(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user)->replicate();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('A factor is removed by its id.');

        DB::transaction(fn () => $this->removal()->remove($user, self::APPLICATION, $factor, new Collection([$factor])));
    }

    /**
     * Erasing deletes the factor and its association and stops its proofs
     * counting, with none of the rest of a removal: another factor, the
     * recovery codes and the other sessions are left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testErasingDeletesOnlyTheFactorsOwnRecords(): void
    {
        $this->enablePasskeys();

        $user    = $this->signedInPerson();
        $other   = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->stepUpWith($user, $other);
        $this->stepUpWith($user, $passkey);

        $generation = VerificationGeneration::current($user);

        $this->removal()->erase($user, $passkey);

        self::assertFalse(Factor::query()->whereKey($passkey->id)->exists());
        self::assertTrue(Factor::query()->whereKey($other->id)->exists());
        self::assertSame(0, PasskeyAssociation::query()->where('factor_id', $passkey->id)->count());
        self::assertSame($generation, VerificationGeneration::current($user));

        $proofs = $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION);

        self::assertSame([$other->id], array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs));
    }

    /**
     * The removal under test.
     *
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function removal(): FactorRemoval
    {
        return $this->container()->make(FactorRemoval::class);
    }
}
