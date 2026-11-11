<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationGeneration::class)]
final class VerificationGenerationTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return void
     */
    public function testAnIdentityWithNoRowIsAtGenerationZero(): void
    {
        self::assertSame(0, VerificationGeneration::current($this->user(7)));
        self::assertSame(0, IdentityState::query()->count());
    }

    /**
     * Advancing creates the identity's row and returns the new generation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdvanceMovesTheGenerationOnByOne(): void
    {
        $user = $this->user(7);

        self::assertSame(1, VerificationGeneration::advance($user));
        self::assertSame(1, VerificationGeneration::current($user));
        self::assertSame(2, VerificationGeneration::advance($user));
        self::assertSame(2, VerificationGeneration::current($user));

        $state = IdentityState::query()->sole();

        self::assertSame(TestUser::class, $state->authenticatable_type);
        self::assertSame('7', $state->authenticatable_id);
        self::assertSame(2, $state->verification_generation);
    }

    /**
     * A row the factor state lock already created.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdvanceKeepsAnExistingRow(): void
    {
        $user = $this->user(7);

        FactorStateTransaction::forIdentity($user, new Factor, static fn (): null => null);

        self::assertSame(1, VerificationGeneration::advance($user));
        self::assertSame(1, IdentityState::query()->count());
    }

    /**
     * Deleting the row between the lock and the increment stands in for a key
     * the database coerced. It rolls back whole.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAdvanceThatChangesNoRowIsRefused(): void
    {
        $user = $this->user(7);

        DB::connection()->beforeExecuting(static function (string $query, array $bindings, Connection $connection): void {

            if (!str_contains($query, 'verification_generation') || !str_starts_with($query, 'update')) {
                return;
            }

            $connection->getPdo()->exec('delete from mfa_identity_states');
        });

        try {
            VerificationGeneration::advance($user);

            self::fail('An advance that changes no row must be refused.');
        } catch (\LogicException $refusal) {
            self::assertStringContainsString('not advanced', $refusal->getMessage());
        }

        self::assertSame(0, IdentityState::query()->count());
    }

    /**
     * Including one of another type that shares its key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdvanceMovesOnlyItsOwnIdentity(): void
    {
        $secondary = new SecondaryUser;

        $secondary->setAttribute('id', 7);

        VerificationGeneration::advance($this->user(7));

        self::assertSame(0, VerificationGeneration::current($this->user(8)));
        self::assertSame(0, VerificationGeneration::current($secondary));
    }

    /**
     * Keyed by its class name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANonEloquentIdentityHasAGeneration(): void
    {
        $identity = new NonEloquentIdentity('ext-1');

        VerificationGeneration::advance($identity);

        self::assertSame(1, VerificationGeneration::current($identity));
        self::assertSame(NonEloquentIdentity::class, IdentityState::query()->sole()->authenticatable_type);
    }

    /**
     * An advance inside the identity's factor state transaction joins it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAdvanceRollsBackWithTheChangeItBelongsTo(): void
    {
        $user = $this->user(7);

        try {
            FactorStateTransaction::forIdentity($user, new Factor, static function () use ($user): never {

                VerificationGeneration::advance($user);

                throw new \RuntimeException('The change failed.');
            });
        } catch (\RuntimeException) {
            // The change failed, so its advance must not have committed.
        }

        self::assertSame(0, VerificationGeneration::current($user));
    }

    /**
     * Refused rather than sharing one.
     *
     * @return void
     */
    public function testRefusesAnIdentityWhoseKeyCannotNameARow(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);

        VerificationGeneration::current(new NonScalarIdentifierUser);
    }

    /**
     * @param  int  $id
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(int $id): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', $id);

        return $user;
    }
}
