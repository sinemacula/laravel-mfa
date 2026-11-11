<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Support\IdentityType;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Identities\FactorHoldingRecord;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetsTheFactorsByTheModelsOwnerColumns(): void
    {
        $table = TableNames::of(TableNames::FACTORS);

        Schema::table($table, static function (Blueprint $blueprint): void {
            $blueprint->renameColumn('authenticatable_type', 'owner_type');
            $blueprint->renameColumn('authenticatable_id', 'owner_id');
        });

        config()->set('mfa.factor.model', RemappedOwnerFactor::class);

        $forgotten = new NonEloquentIdentity(identifier: 'plain-7');
        $kept      = new NonEloquentIdentity(identifier: 'plain-8');

        foreach ([$forgotten, $kept] as $identity) {
            (new RemappedOwnerFactor)->forceFill([
                'owner_type' => IdentityType::of($identity),
                'owner_id'   => ProofOwner::of($identity)->key,
                'type'       => 'totp',
            ])->save();
        }

        $this->container()->make(ForgetIdentity::class)->forget($forgotten);

        self::assertSame(0, DB::table($table)->where('owner_id', 'plain-7')->count());
        self::assertSame(1, DB::table($table)->where('owner_id', 'plain-8')->count());
    }

    /**
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
     * One record in every table.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    private function giveRecords(Authenticatable $identity): void
    {
        $owner = $this->owner($identity);
        $now   = CarbonImmutable::now();

        $factor = Factor::query()->create([...$owner, 'type' => 'totp']);

        Enrollment::query()->create([
            ...$owner,
            'factor_id'   => $factor->id,
            'grant_hash'  => hash('sha256', $factor->id),
            'application' => 'web',
            'session_id'  => 'sign-in-digest',
            'generation'  => 0,
            'authority'   => EnrollmentAuthorization::STEP_UP,
            'expires_at'  => $now,
        ]);
        Code::query()->create([
            ...$owner,
            'factor_id'        => $factor->id,
            'purpose'          => 'sign_in',
            'application'      => 'web',
            'destination_hash' => hash('sha256', 'd' . $factor->id),
            'code_hash'        => hash('sha256', 'c' . $factor->id),
            'sent_at'          => $now,
            'sent_times'       => [$now->getTimestamp()],
            'expires_at'       => $now,
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
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return array{authenticatable_type: string, authenticatable_id: string}
     */
    private function owner(Authenticatable $identity): array
    {
        /** @var int|string $key */
        $key = $identity->getAuthIdentifier();

        return ['authenticatable_type' => IdentityType::of($identity), 'authenticatable_id' => (string) $key];
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function createUser(string $email): TestUser
    {
        return TestUser::query()->create(['email' => $email, 'mfa_enabled' => true]);
    }
}
