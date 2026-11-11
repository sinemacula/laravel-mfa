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
use Tests\Fixtures\Factors\EnumStatusFactor;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\FactorHoldingRecord;
use Tests\Fixtures\Identities\SoftDeletingFactorHolder;
use Tests\TestCase;

/**
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
     * Of the shipped model.
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
     * @return void
     */
    public function testAModelThatIsNotAnAuthenticatableFindsItsFactorsByItsKey(): void
    {
        $identity = $this->createHolder('one@example.test');
        $own      = $this->createFactor($identity, 'confirmed');

        $record = new FactorHoldingRecord;

        $record->setAttribute('id', $identity->id);

        Factor::query()->whereKey($own->id)->update(['authenticatable_type' => $record->getMorphClass()]);

        self::assertSame([$own->id], $record->authFactors()->pluck('id')->all());
    }

    /**
     * @return void
     */
    public function testTheFactorsAreOfTheConfiguredModel(): void
    {
        $this->container()->make(Repository::class)->set('mfa.factor.model', CustomFactor::class);

        self::assertInstanceOf(CustomFactor::class, (new FactorHolder)->authFactors()->getModel());
    }

    /**
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
     * Only a reset clears them.
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
     * Only exactly `pending` does not, so a corrupt status never reads as no
     * factor, whatever the collation.
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
     * Where a column allows that.
     *
     * @return void
     */
    public function testAFactorWithNoStatusEnablesMfa(): void
    {
        Schema::table('mfa_factors', static function (Blueprint $table): void {
            $table->string('status', 16)->nullable()->default(null)->change();
        });

        $identity = $this->createHolder('one@example.test');

        Factor::query()->create([
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
            'type'                 => 'totp',
            'status'               => null,
        ]);

        self::assertNull(Factor::query()->value('status'));
        self::assertTrue($identity->isMfaEnabled());
    }

    /**
     * Pending does not count; confirmed does, and so does a value the enum does
     * not know.
     *
     * @return void
     */
    public function testAnEnumCastStatusIsReadAsStored(): void
    {
        $this->container()->make(Repository::class)->set('mfa.factor.model', EnumStatusFactor::class);

        $identity = $this->createHolder('one@example.test');
        $factor   = fn (string $status): EnumStatusFactor => EnumStatusFactor::query()->create([
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
            'type'                 => 'totp',
            'status'               => $status,
        ]);

        $pending = $factor('pending');

        self::assertFalse($identity->isMfaEnabled());

        EnumStatusFactor::query()->whereKey($pending->getKey())->toBase()->update(['status' => 'CONFIRMED']);

        self::assertTrue($identity->isMfaEnabled());

        EnumStatusFactor::query()->whereKey($pending->getKey())->toBase()->update(['status' => 'pending']);
        $factor('confirmed');

        self::assertTrue($identity->isMfaEnabled());
    }

    /**
     * And only its own.
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
     * The identity is never left without them.
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
     * The delete targets a missing table in its own transaction, so every
     * driver refuses it and PostgreSQL's test transaction stays usable.
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
     * A restored identity still has them.
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
     * Not by the shipped ones.
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
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\FactorHolder
     */
    private function createHolder(string $email): FactorHolder
    {
        return FactorHolder::query()->create(['email' => $email]);
    }

    /**
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
