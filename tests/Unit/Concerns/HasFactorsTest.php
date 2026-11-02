<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\CustomFactor;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\SoftDeletingFactorHolder;
use Tests\TestCase;

/**
 * Unit tests for the `HasFactors` trait: an identity model's factors, whether
 * it has a confirmed one, and the defaults of the questions every operation
 * asks first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasFactors::class)]
final class HasFactorsTest extends TestCase
{
    use RefreshDatabase;

    /**
     * By default the identity is a person, active, and requires nothing of its
     * own.
     *
     * @return void
     */
    public function testTheDefaultsAreAnActivePersonRequiringNothing(): void
    {
        $identity = new FactorHolder;

        self::assertTrue($identity->canHoldFactors());
        self::assertTrue($identity->isMfaActive());
        self::assertNull($identity->requiresAdditionalFactor());
    }

    /**
     * The identity's factors are its own, of the shipped model.
     *
     * @return void
     */
    public function testTheFactorsAreTheIdentitysOwn(): void
    {
        $identity = $this->createHolder('one@example.test');
        $other    = $this->createHolder('two@example.test');

        $own = $this->createFactor($identity, 'confirmed');
        $this->createFactor($other, 'confirmed');

        $factors = $identity->authFactors()->get();

        self::assertInstanceOf(Factor::class, $identity->authFactors()->getModel());
        self::assertSame([$own->id], $factors->modelKeys());
    }

    /**
     * The factors are of the configured factor model.
     *
     * @return void
     */
    public function testTheFactorsAreOfTheConfiguredModel(): void
    {
        $this->container()->make(Repository::class)->set('mfa.factor.model', CustomFactor::class);

        self::assertInstanceOf(CustomFactor::class, (new FactorHolder)->authFactors()->getModel());
    }

    /**
     * Only a confirmed factor enables MFA: a pending one does not.
     *
     * @return void
     */
    public function testOnlyAConfirmedFactorEnablesMfa(): void
    {
        $identity = $this->createHolder('one@example.test');

        self::assertFalse($identity->isMfaEnabled());

        $this->createFactor($identity, 'pending');

        self::assertFalse($identity->isMfaEnabled());

        $this->createFactor($identity, 'confirmed');

        self::assertTrue($identity->isMfaEnabled());
    }

    /**
     * Stored statuses that are none the package knows, which only a reset
     * clears.
     *
     * @return iterable<string, array{string}>
     */
    public static function unknownStatuses(): iterable
    {
        yield 'another case of confirmed' => ['CONFIRMED'];
        yield 'another case of pending' => ['PENDING'];
        yield 'pending, padded' => ['pending '];
        yield 'another word' => ['retired'];
        yield 'empty' => [''];
    }

    /**
     * A factor whose stored status is none the package knows holds the identity
     * to MFA as a confirmed one does: only exactly `pending` does not, so a
     * corrupt status is never read as having no factor, on a database whose
     * collation ignores case and padding as on any other.
     *
     * @param  string  $status
     * @return void
     */
    #[DataProvider('unknownStatuses')]
    public function testAFactorOfAnUnknownStatusEnablesMfa(string $status): void
    {
        $identity = $this->createHolder('one@example.test');

        $this->createFactor($identity, 'pending');
        $this->createFactor($identity, $status);

        self::assertTrue($identity->isMfaEnabled());
    }

    /**
     * Deleting the identity deletes its factors, and only its own.
     *
     * @return void
     */
    public function testDeletingTheIdentityDeletesItsFactors(): void
    {
        $identity = $this->createHolder('one@example.test');
        $other    = $this->createHolder('two@example.test');

        $this->createFactor($identity, 'confirmed');
        $kept = $this->createFactor($other, 'confirmed');

        $identity->delete();

        self::assertSame([$kept->id], Factor::query()->pluck('id')->all());
    }

    /**
     * A delete another `deleting` listener cancels keeps the identity's
     * factors: the identity is never left without them.
     *
     * @return void
     */
    public function testACanceledDeleteKeepsTheFactors(): void
    {
        $identity = $this->createHolder('one@example.test');
        $factor   = $this->createFactor($identity, 'confirmed');

        FactorHolder::deleting(static fn (): bool => false);

        self::assertFalse($identity->delete());
        self::assertTrue(FactorHolder::query()->whereKey($identity->id)->exists());
        self::assertSame([$factor->id], Factor::query()->pluck('id')->all());
    }

    /**
     * A delete the database refuses keeps the identity's factors.
     *
     * The delete is aimed at a table that does not exist, which every driver
     * refuses without a schema change, and runs in a transaction of its own so
     * the refusal leaves the test's transaction usable on PostgreSQL.
     *
     * @return void
     */
    public function testAFailedDeleteKeepsTheFactors(): void
    {
        $identity = $this->createHolder('one@example.test');
        $factor   = $this->createFactor($identity, 'confirmed');

        $identity->setTable('missing_test_users');

        try {
            DB::transaction(static fn (): ?bool => $identity->delete());
            self::fail('The delete was expected to fail.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
        }

        self::assertTrue(FactorHolder::query()->whereKey($identity->id)->exists());
        self::assertSame([$factor->id], Factor::query()->pluck('id')->all());
    }

    /**
     * A soft delete keeps the identity's factors, so a restored identity still
     * has them; a force delete deletes them.
     *
     * @return void
     */
    public function testASoftDeleteKeepsTheFactorsAndAForceDeleteDeletesThem(): void
    {
        $identity = SoftDeletingFactorHolder::query()->create(['email' => 'soft@example.test']);
        $factor   = Factor::query()->create([
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        $identity->delete();

        self::assertTrue($identity->trashed());
        self::assertSame([$factor->id], Factor::query()->pluck('id')->all());

        // @phpstan-ignore staticMethod.dynamicCall
        $identity->restore();

        self::assertTrue($identity->isMfaEnabled());

        $identity->forceDelete();

        self::assertSame(0, Factor::query()->count());
    }

    /**
     * The factors are found by the owner columns the configured model's
     * relation names, not by the shipped ones.
     *
     * @return void
     */
    public function testTheFactorsAreFoundByTheModelsOwnerColumns(): void
    {
        Schema::table('mfa_factors', static function (Blueprint $blueprint): void {
            $blueprint->renameColumn('authenticatable_type', 'owner_type');
            $blueprint->renameColumn('authenticatable_id', 'owner_id');
        });

        $this->container()->make(Repository::class)->set('mfa.factor.model', RemappedOwnerFactor::class);

        $identity = $this->createHolder('one@example.test');
        $other    = $this->createHolder('two@example.test');

        $own = $this->createRemappedFactor($identity);
        $this->createRemappedFactor($other);

        self::assertSame([$own->id], $identity->authFactors()->pluck('id')->all());
        self::assertTrue($identity->isMfaEnabled());
    }

    /**
     * Create a confirmed factor of the identity through the remapped owner
     * columns.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $identity
     * @return \Tests\Fixtures\Factors\RemappedOwnerFactor
     */
    private function createRemappedFactor(FactorHolder $identity): RemappedOwnerFactor
    {
        $factor = new RemappedOwnerFactor;

        $factor->forceFill([
            'owner_type' => $identity->getMorphClass(),
            'owner_id'   => (string) $identity->id,
            'type'       => 'totp',
            'status'     => 'confirmed',
        ])->save();

        return $factor;
    }

    /**
     * Create an identity.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\FactorHolder
     */
    private function createHolder(string $email): FactorHolder
    {
        return FactorHolder::query()->create(['email' => $email]);
    }

    /**
     * Create a factor of the identity with the given status.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $identity
     * @param  string  $status
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function createFactor(FactorHolder $identity, string $status): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
            'type'                 => 'totp',
            'status'               => $status,
        ]);
    }
}
