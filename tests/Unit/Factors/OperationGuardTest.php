<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `OperationGuard`, the guard every operation on an identity's
 * factors starts with: the matrix of what it refuses (a machine, an inactive
 * identity, another identity's factor, a pending factor, a type the application
 * does not enable), in its order, and what it lets through.
 *
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
     * Rows of an identity and the reason the guard refuses it.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, \SineMacula\Laravel\Mfa\Enums\FailureReason}>
     */
    public static function refusedIdentities(): iterable
    {
        yield 'a machine identity' => [new NonEloquentIdentity(person: false), FailureReason::MACHINE_IDENTITY];
        yield 'an inactive identity' => [new NonEloquentIdentity(active: false), FailureReason::IDENTITY_INACTIVE];
        yield 'an inactive machine, refused as a machine first' => [new NonEloquentIdentity(person: false, active: false), FailureReason::MACHINE_IDENTITY];
    }

    /**
     * A machine or an inactive identity is refused, on its own and before its
     * factor is looked up.
     *
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
     * A person who is active passes the identity checks.
     *
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
     * The bound subject type resolver is the authority on who is a person: one
     * that finds a person a machine is honoured.
     *
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
     * The identity's own confirmed factor of an enabled type is returned, as
     * stored.
     *
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
     * A non-Eloquent identity's factor is found by its class name and key.
     *
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
     * Another identity's factor is not found, exactly as an id that does not
     * exist is not, whether the owner differs by key or by type.
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
     * Rows of a factor id the guard cannot look a factor up by.
     *
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
     * An id that is neither a string nor an integer finds nothing.
     *
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
     * An identity whose key is neither a string nor an integer owns nothing.
     *
     * @return void
     */
    public function testAnIdentityWithAKeyOfAnotherShapeOwnsNothing(): void
    {
        $factor = $this->createFactor(NonEloquentIdentity::class, '1');

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor(new NonEloquentIdentity(identifier: 1.0), $factor->id, self::APPLICATION)));
    }

    /**
     * An integer factor id is looked up as the key it names.
     *
     * @return void
     */
    public function testAnIntegerIdIsLookedUp(): void
    {
        $user = $this->createUser();

        $this->createFactor($user->getMorphClass(), (string) $user->id);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->guard()->factor($user, 1, self::APPLICATION)));
    }

    /**
     * A pending factor is refused where the operation needs a confirmed one,
     * and returned where it takes a pending one.
     *
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
     * A factor whose type the application does not enable is refused, as is
     * every factor through an application that is not configured; a pending
     * factor is refused as pending first.
     *
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
     * A refusal names its reason and a detail, never the factor's owner.
     *
     * @return void
     */
    public function testARefusalCarriesItsReasonAndDetail(): void
    {
        $exception = new OperationRefusedException(FailureReason::NOT_FOUND, 'The identity has no factor with that id.');

        self::assertSame(FailureReason::NOT_FOUND, $exception->reason);
        self::assertSame('The identity has no factor with that id.', $exception->getMessage());
    }

    /**
     * Resolve the guard.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\OperationGuard
     */
    private function guard(): OperationGuard
    {
        return $this->container()->make(OperationGuard::class);
    }

    /**
     * The reason the call is refused with.
     *
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
     * Create a test user.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function createUser(string $email = 'person@example.test'): TestUser
    {
        return TestUser::query()->create(['email' => $email, 'mfa_enabled' => true]);
    }

    /**
     * Create a factor owned by the given type and key.
     *
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
