<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use Tests\Fixtures\Identities\FactorHoldingRecord;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `ForgetIdentity`, which deletes everything the package holds
 * for an identity being deleted, and the `HasFactors` trait's deleting hook
 * that calls it: the identity's factors, enrolments, codes, recovery codes,
 * passkey associations and factor state go, and another identity's stay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetIdentity::class)]
final class ForgetIdentityTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Forgetting an identity deletes its records in every table and leaves
     * another identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletesEveryRecordOfTheIdentityAndNoOther(): void
    {
        $forgotten = $this->createUser('forgotten@example.test');
        $kept      = $this->createUser('kept@example.test');

        $this->giveRecords($forgotten);
        $this->giveRecords($kept);

        $this->container()->make(ForgetIdentity::class)->forget($forgotten);

        self::assertSame(array_fill_keys($this->tables(), 0), $this->counts($forgotten));
        self::assertSame(array_fill_keys($this->tables(), 1), $this->counts($kept));
    }

    /**
     * Deleting an Eloquent identity that uses the trait forgets it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAnIdentityModelForgetsIt(): void
    {
        $user = $this->createUser('deleted@example.test');

        $this->giveRecords($user);

        $user->delete();

        self::assertSame(array_fill_keys($this->tables(), 0), $this->counts($user));
    }

    /**
     * Deleting a model that uses the trait but is not an identity forgets
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAModelThatIsNotAnIdentityForgetsNothing(): void
    {
        $user = $this->createUser('owner@example.test');

        $this->giveRecords($user);

        $model = new FactorHoldingRecord;

        $model->setAttribute('id', $user->id);
        $model->exists = true;

        $model->delete();

        self::assertSame(array_fill_keys($this->tables(), 1), $this->counts($user));
    }

    /**
     * An identity that is not an Eloquent model is forgotten by its class name
     * and key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgetsAnIdentityThatIsNotAModel(): void
    {
        $identity = new NonEloquentIdentity(identifier: 'plain-9');

        $this->giveRecords($identity);

        $this->container()->make(ForgetIdentity::class)->forget($identity);

        self::assertSame(array_fill_keys($this->tables(), 0), $this->counts($identity));
    }

    /**
     * An integer key is matched as the string the owner columns store.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIntegerKeyIsMatchedAsAString(): void
    {
        $identity = new NonEloquentIdentity(identifier: 12);

        $this->giveRecords($identity);

        $this->container()->make(ForgetIdentity::class)->forget($identity);

        self::assertSame(array_fill_keys($this->tables(), 0), $this->counts($identity));
    }

    /**
     * Give the identity one record in every table.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    private function giveRecords(Authenticatable $identity): void
    {
        $owner = $this->owner($identity);
        $now   = CarbonImmutable::now();

        $factor = Factor::query()->create([...$owner, 'type' => 'totp']);

        Enrollment::query()->create([...$owner, 'factor_id' => $factor->id, 'grant_hash' => hash('sha256', $factor->id), 'application' => 'web', 'expires_at' => $now]);
        Code::query()->create([
            ...$owner,
            'factor_id'   => $factor->id,
            'purpose'     => 'sign_in',
            'application' => 'web',
            'code_hash'   => hash('sha256', 'c' . $factor->id),
            'sent_at'     => $now,
            'expires_at'  => $now,
        ]);
        RecoveryCode::query()->create([...$owner, 'code_hash' => 'hash', 'generation' => 1]);
        PasskeyAssociation::query()->create([
            ...$owner,
            'factor_id'          => $factor->id,
            'credential_id_hash' => hash('sha256', 'p' . $factor->id),
            'credential_id'      => 'credential',
        ]);
        IdentityState::query()->create($owner);
    }

    /**
     * How many records the identity has in each table.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return array<string, int>
     */
    private function counts(Authenticatable $identity): array
    {
        $counts = [];

        foreach ($this->tables() as $table) {
            $counts[$table] = DB::table($table)->where($this->owner($identity))->count();
        }

        return $counts;
    }

    /**
     * The tables that hold records by owner.
     *
     * @return list<string>
     */
    private function tables(): array
    {
        return array_map(TableNames::of(...), [
            TableNames::FACTORS,
            TableNames::ENROLLMENTS,
            TableNames::CODES,
            TableNames::RECOVERY_CODES,
            TableNames::PASSKEY_ASSOCIATIONS,
            TableNames::IDENTITY_STATES,
        ]);
    }

    /**
     * The identity's owner columns.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return array{authenticatable_type: string, authenticatable_id: string}
     */
    private function owner(Authenticatable $identity): array
    {
        /** @var int|string $key */
        $key = $identity->getAuthIdentifier();

        return ['authenticatable_type' => CurrentIdentity::typeOf($identity), 'authenticatable_id' => (string) $key];
    }

    /**
     * Create a test user.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function createUser(string $email): TestUser
    {
        return TestUser::query()->create(['email' => $email, 'mfa_enabled' => true]);
    }
}
