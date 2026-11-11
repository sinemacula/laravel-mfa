<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use Tests\Fixtures\Factors\SecondaryConnectionFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorStateTransaction::class)]
final class FactorStateTransactionTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsTheCallbackInATransactionAndReturnsItsResult(): void
    {
        $user  = $this->createUser('one@example.test');
        $level = DB::connection()->transactionLevel();

        $result = FactorStateTransaction::forIdentity($user, new Factor, static fn (): int => DB::connection()->transactionLevel());

        self::assertSame($level + 1, $result);
        self::assertSame($level, DB::connection()->transactionLevel());
    }

    /**
     * Another identity's factors are not included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHandsTheCallbackTheIdentitysStoredFactors(): void
    {
        $user  = $this->createUser('one@example.test');
        $other = $this->createUser('two@example.test');

        $first  = $this->createFactor($user, 'totp');
        $second = $this->createFactor($user, 'email');
        $this->createFactor($other, 'totp');

        Factor::query()->whereKey($second->getKey())->update(['label' => 'Stored']);

        $factors = FactorStateTransaction::forIdentity($user, new Factor, static fn (Collection $factors): Collection => $factors);

        self::assertEqualsCanonicalizing([$first->getKey(), $second->getKey()], $factors->modelKeys());
        $stored = $factors->first(static fn (Model $factor): bool => $factor->is($second));

        self::assertSame('Stored', $stored?->getAttribute('label'));
    }

    /**
     * One row per identity, created on its first change and touched by each
     * one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatesOneStateRowPerIdentityAndTouchesItOnEachChange(): void
    {
        $user = $this->createUser('one@example.test');

        CarbonImmutable::setTestNow('2026-01-01 10:00:00');

        FactorStateTransaction::forIdentity($user, new Factor, static fn (): null => null);

        CarbonImmutable::setTestNow('2026-01-01 11:00:00');

        FactorStateTransaction::forIdentity($user, new Factor, static fn (): null => null);

        $rows = DB::table('mfa_identity_states')->get();

        self::assertCount(1, $rows);

        $row = $rows->first();

        self::assertIsObject($row);
        self::assertSame($user->getMorphClass(), $row->authenticatable_type);
        self::assertSame((string) $user->id, $row->authenticatable_id);
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $row->id);
        self::assertSame('2026-01-01 10:00:00', CarbonImmutable::parse($row->created_at)->format('Y-m-d H:i:s'));
        self::assertSame('2026-01-01 11:00:00', CarbonImmutable::parse($row->updated_at)->format('Y-m-d H:i:s'));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testLocksANonEloquentIdentityByItsClassAndKey(): void
    {
        FactorStateTransaction::forIdentity(new NonEloquentIdentity('plain-7'), new Factor, static fn (): null => null);

        $row = DB::table('mfa_identity_states')->first();

        self::assertIsObject($row);
        self::assertSame(NonEloquentIdentity::class, $row->authenticatable_type);
        self::assertSame('plain-7', $row->authenticatable_id);
    }

    /**
     * The owner is read from the factor's owner columns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLocksTheOwnerOfAFactor(): void
    {
        $user  = $this->createUser('one@example.test');
        $other = $this->createUser('two@example.test');

        $factor = $this->createFactor($user, 'totp');
        $this->createFactor($other, 'totp');

        $factors = FactorStateTransaction::forFactor($factor, static fn (Collection $factors): Collection => $factors);

        self::assertSame([$factor->getKey()], $factors->modelKeys());

        $row = DB::table('mfa_identity_states')->first();

        self::assertIsObject($row);
        self::assertSame((string) $user->id, $row->authenticatable_id);
    }

    /**
     * The owner is named by the factor's owner columns and never built.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLocksTheNonEloquentOwnerOfAFactor(): void
    {
        $factor = Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-3',
            'type'                 => 'totp',
        ]);

        $factors = FactorStateTransaction::forFactor($factor, static fn (Collection $factors): Collection => $factors);

        self::assertSame([$factor->getKey()], $factors->modelKeys());

        $row = DB::table('mfa_identity_states')->first();

        self::assertIsObject($row);
        self::assertSame(NonEloquentIdentity::class, $row->authenticatable_type);
        self::assertSame('plain-3', $row->authenticatable_id);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmptyTableSettingNamesTheDefaultTable(): void
    {
        Config::set('mfa.identity_state.table', '');

        FactorStateTransaction::forIdentity($this->createUser('one@example.test'), new Factor, static fn (): null => null);

        Config::set('mfa.identity_state', []);

        FactorStateTransaction::forIdentity($this->createUser('two@example.test'), new Factor, static fn (): null => null);

        self::assertSame(2, DB::table('mfa_identity_states')->count());
    }

    /**
     * Refused before the transaction opens, so nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAFactorModelOffTheStorageConnection(): void
    {
        $user = $this->createUser('one@example.test');

        try {
            FactorStateTransaction::forIdentity($user, new SecondaryConnectionFactor, static fn (): null => null);
            self::fail('A factor model on another connection must be refused.');
        } catch (ModelOffStorageConnectionException $exception) {
            self::assertStringContainsString('mfa.factor.model class', $exception->getMessage());
        }

        self::assertSame(0, DB::table('mfa_identity_states')->count());
    }

    /**
     * Refused rather than collapsed onto a shared lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnIdentityWhoseKeyIsNotAStringOrAnInteger(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage('An owner key must be a non-empty string or an integer to lock its factor state; got [stdClass].');

        FactorStateTransaction::forIdentity(new NonScalarIdentifierUser, new Factor, static fn (): null => null);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnIdentityWithAnEmptyKey(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage('got [string]');

        FactorStateTransaction::forIdentity(new NonEloquentIdentity(''), new Factor, static fn (): null => null);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testLocksAnIntegerKeyAsItsStringForm(): void
    {
        FactorStateTransaction::forIdentity(new NonEloquentIdentity(42), new Factor, static fn (): null => null);

        self::assertSame('42', DB::table('mfa_identity_states')->value('authenticatable_id'));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAFactorWithoutAnOwnerType(): void
    {
        $factor = new Factor(['authenticatable_id' => '1', 'type' => 'totp']);

        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage('The factor names no owner type, so its owner\'s factor state cannot be locked.');

        FactorStateTransaction::forFactor($factor, static fn (): null => null);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAFactorWithAnEmptyOwnerType(): void
    {
        $factor = new Factor(['authenticatable_type' => '', 'authenticatable_id' => '1', 'type' => 'totp']);

        $this->expectException(UnsupportedIdentifierException::class);

        FactorStateTransaction::forFactor($factor, static fn (): null => null);
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function createUser(string $email): TestUser
    {
        return TestUser::query()->create(['email' => $email, 'mfa_enabled' => true]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $driver
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function createFactor(TestUser $user, string $driver): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => $driver,
        ]);
    }
}
