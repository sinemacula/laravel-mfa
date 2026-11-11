<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Context\InvertedActiveState;
use Tests\Fixtures\Factors\IntegerKeyedFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationGuard::class)]
#[CoversClass(OperationRefusedException::class)]
final class OperationGuardTest extends TestCase
{
    use RefreshDatabase;

    /** @var string The application the operations run through. */
    private const string APPLICATION = 'web';

    /**
     * Enable TOTP for the application the operations run through.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container()->make(Repository::class)->set('mfa.applications.' . self::APPLICATION, ['types' => ['totp']]);
    }

    /**
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, \SineMacula\Laravel\Mfa\Enums\FailureReason}>
     */
    public static function refusedIdentities(): iterable
    {
        yield 'a machine identity' => [new NonEloquentIdentity(person: false), FailureReason::MACHINE_IDENTITY];
        yield 'an inactive identity' => [new NonEloquentIdentity(active: false), FailureReason::IDENTITY_INACTIVE];
        yield 'an inactive machine, refused as a machine first' => [new NonEloquentIdentity(person: false, active: false), FailureReason::MACHINE_IDENTITY];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('refusedIdentities')]
    public function testRefusesTheIdentity(MultiFactorAuthenticatable $identity, FailureReason $reason): void
    {
        $factor = $this->createFactor(NonEloquentIdentity::class, 'plain-1');

        self::assertSame($reason, $this->refusal(fn () => $this->guard()->identity($identity)));
        self::assertSame($reason, $this->refusal(fn () => $this->guard()->factor($identity, $factor->id, self::APPLICATION)));
    }

    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function testLetsAnActivePersonThrough(): void
    {
        $this->guard()->identity(new NonEloquentIdentity);

        $this->addToAssertionCount(1);
    }

    /**
     * @return void
     */
    public function testTheBoundSubjectTypeResolverDecidesWhoIsAPerson(): void
    {
        $resolver = \Mockery::mock(SubjectTypeResolver::class);
        $resolver->shouldReceive('isPerson')->andReturnFalse();

        $this->container()->instance(SubjectTypeResolver::class, $resolver);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $this->refusal(fn () => $this->guard()->identity(new NonEloquentIdentity)));
    }

    /**
     * @return void
     */
    public function testTheBoundActiveStateResolverDecidesWhoIsActive(): void
    {
        $this->container()->instance(ActiveStateResolver::class, new InvertedActiveState);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->refusal(fn () => $this->guard()->identity(new NonEloquentIdentity)));
        self::assertNull($this->refusal(fn () => $this->guard()->identity(new NonEloquentIdentity(active: false))));
    }

    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function testReturnsTheIdentitysConfirmedFactorOfAnEnabledType(): void
    {
        $user   = $this->createUser();
        $factor = $this->createFactor($user->getMorphClass(), (string) $user->id);

        $found = $this->guard()->factor($user, $factor->id, self::APPLICATION);

        self::assertInstanceOf(Factor::class, $found);
        self::assertSame($factor->id, $found->getFactorIdentifier());
    }

    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function testFindsANonEloquentIdentitysFactor(): void
    {
        $factor = $this->createFactor(NonEloquentIdentity::class, 'plain-1');

        self::assertSame($factor->id, $this->guard()->factor(new NonEloquentIdentity, $factor->id, self::APPLICATION)->getFactorIdentifier());
    }

    /**
     * Exactly as an id that does not exist is not.
     *
     * @return void
     */
    public function testAnotherIdentitysFactorIsNotFound(): void
    {
        $owner    = $this->createUser('owner@example.test');
        $intruder = $this->createUser('intruder@example.test');

        $byKey  = $this->createFactor($owner->getMorphClass(), (string) $owner->id);
        $byType = $this->createFactor(NonEloquentIdentity::class, (string) $intruder->id);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($intruder, $byKey->id, self::APPLICATION)));
        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($intruder, $byType->id, self::APPLICATION)));
        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($intruder, '01JUNKNOWNFACTOR0000000000', self::APPLICATION)));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unusableIds(): iterable
    {
        yield 'null' => [null];
        yield 'an array' => [['01J']];
        yield 'an object' => [new \stdClass];
        yield 'a float' => [1.0];
    }

    /**
     * @param  mixed  $id
     * @return void
     */
    #[DataProvider('unusableIds')]
    public function testAnIdOfAnotherShapeIsNotFound(mixed $id): void
    {
        $user = $this->createUser();

        $this->createFactor($user->getMorphClass(), (string) $user->id);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($user, $id, self::APPLICATION)));
    }

    /**
     * @return void
     */
    public function testAnIdentityWithAKeyOfAnotherShapeOwnsNothing(): void
    {
        $factor = $this->createFactor(NonEloquentIdentity::class, '1');

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor(new NonEloquentIdentity(identifier: 1.0), $factor->id, self::APPLICATION)));
    }

    /**
     * @return void
     */
    public function testAnIntegerIdIsLookedUp(): void
    {
        $user = $this->createUser();

        $this->createFactor($user->getMorphClass(), (string) $user->id);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($user, 1, self::APPLICATION)));
    }

    /**
     * Owner or id columns that may differ only in case from what is asked for.
     *
     * @return iterable<string, array{string}>
     */
    public static function differentCases(): iterable
    {
        yield 'the owner type' => ['authenticatable_type'];
        yield 'the owner key' => ['authenticatable_id'];
        yield 'the factor id' => ['id'];
    }

    /**
     * The row found must hold exactly the owner and the id asked for.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('differentCases')]
    public function testACollationMatchDifferingOnlyInCaseIsNotFound(string $column): void
    {
        $this->makeCaseInsensitive();

        $identity = new NonEloquentIdentity('plain-key');
        $factor   = $this->createFactor(NonEloquentIdentity::class, 'plain-key');
        $stored   = $factor->getAttribute($column);

        self::assertIsString($stored);

        $changed = strtoupper($stored);

        self::assertNotSame($stored, $changed);

        if ($column !== 'id') {
            Factor::query()->whereKey($factor->id)->update([$column => $changed]);
        }

        $id = $column === 'id' ? $changed : $factor->id;

        $matches = Factor::query()->whereKey($id)->where('authenticatable_type', NonEloquentIdentity::class)->where('authenticatable_id', 'plain-key');

        self::assertSame(1, $matches->count(), 'The collation must match the row.');
        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($identity, $id, self::APPLICATION)));
    }

    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function testAnIntegerAndAStringFormOfOneIdAreEqual(): void
    {
        config()->set('mfa.factor.model', IntegerKeyedFactor::class);
        config()->set('mfa.factor.table', 'test_integer_keyed_factors');

        $identity = new NonEloquentIdentity('plain-key');

        $factor = IntegerKeyedFactor::query()->forceCreate([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-key',
            'type'                 => 'totp',
            'status'               => FactorStatus::CONFIRMED->value,
        ]);

        self::assertIsInt($factor->getKey());
        self::assertSame($factor->getKey(), $this->guard()->factor($identity, $factor->getKey(), self::APPLICATION)->getKey());
        self::assertSame($factor->getKey(), $this->guard()->factor($identity, (string) $factor->getKey(), self::APPLICATION)->getKey());
    }

    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function testAPendingFactorIsRefusedUnlessTheOperationTakesOne(): void
    {
        $user   = $this->createUser();
        $factor = $this->createFactor($user->getMorphClass(), (string) $user->id, FactorStatus::PENDING);

        self::assertSame(FailureReason::NOT_CONFIRMED, $this->refusal(fn () => $this->guard()->factor($user, $factor->id, self::APPLICATION)));
        self::assertSame($factor->id, $this->guard()->factor($user, $factor->id, self::APPLICATION, confirmed: false)->getFactorIdentifier());
    }

    /**
     * @return void
     */
    public function testAFactorOfATypeTheApplicationDoesNotEnableIsRefused(): void
    {
        $user    = $this->createUser();
        $sms     = $this->createFactor($user->getMorphClass(), (string) $user->id, type: 'sms');
        $totp    = $this->createFactor($user->getMorphClass(), (string) $user->id);
        $pending = $this->createFactor($user->getMorphClass(), (string) $user->id, FactorStatus::PENDING, 'sms');

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->refusal(fn () => $this->guard()->factor($user, $sms->id, self::APPLICATION)));
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->refusal(fn () => $this->guard()->factor($user, $totp->id, 'admin')));
        self::assertSame(FailureReason::NOT_CONFIRMED, $this->refusal(fn () => $this->guard()->factor($user, $pending->id, self::APPLICATION)));
    }

    /**
     * @return void
     */
    public function testARefusalCarriesItsReasonAndDetail(): void
    {
        $exception = new OperationRefusedException(FailureReason::NOT_FOUND, 'The identity has no factor with that id.');

        self::assertSame(FailureReason::NOT_FOUND, $exception->reason);
        self::assertSame('The identity has no factor with that id.', $exception->getMessage());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Factors\OperationGuard
     */
    private function guard(): OperationGuard
    {
        return $this->container()->make(OperationGuard::class);
    }

    /**
     * @param  \Closure(): mixed  $call
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    private function refusal(\Closure $call): ?FailureReason
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        return null;
    }

    /**
     * Match the owner columns and the key whatever their case, as a
     * case-insensitive database does.
     *
     * @return void
     */
    private function makeCaseInsensitive(): void
    {
        $connection = DB::connection(StorageConnection::name());
        $table      = TableNames::of(TableNames::FACTORS);

        if ($connection->getDriverName() !== 'sqlite') {
            self::markTestSkipped('The collation is changed through SQLite\'s own schema.');
        }

        $statement = $connection->scalar('select sql from sqlite_master where type = ? and name = ?', ['table', $table]);

        self::assertIsString($statement);

        $connection->statement(sprintf('drop table "%s"', $table));
        $connection->statement(preg_replace('/"(id|authenticatable_type|authenticatable_id)" (varchar|char\(\d+\)) not null/', '$0 collate nocase', $statement) ?? $statement);
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function createUser(string $email = 'person@example.test'): TestUser
    {
        return TestUser::query()->create(['email' => $email, 'mfa_enabled' => true]);
    }

    /**
     * @param  string  $ownerType
     * @param  string  $ownerKey
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorStatus  $status
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function createFactor(string $ownerType, string $ownerKey, FactorStatus $status = FactorStatus::CONFIRMED, string $type = 'totp'): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $ownerType,
            'authenticatable_id'   => $ownerKey,
            'type'                 => $type,
            'status'               => $status->value,
        ]);
    }
}
