<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Support\IdentityType;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Identities\FactorHoldingRecord;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\Concerns\HoldsIdentityRecords;
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
    use HoldsIdentityRecords, RefreshDatabase;

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

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($forgotten));
        self::assertSame($this->eachTableHolding(1), $this->recordCounts($kept));
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

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($user));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAnIdentityKeepsAnotherModelsRecordsUnderTheSameKey(): void
    {
        $deleted = $this->createUser('deleted@example.test');
        $kept    = SecondaryUser::query()->forceCreate(['id' => $deleted->id, 'email' => 'kept@example.test']);

        config()->set('mfa.applications.web', ['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        $this->giveRecords($deleted);
        $this->giveRecords($kept);

        $factor = Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $kept->getMorphClass(),
            'authenticatable_id'   => (string) $kept->id,
            'status'               => 'confirmed',
        ]);

        $before = $this->recordCounts($kept);

        $deleted->delete();

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($deleted));
        self::assertSame($before, $this->recordCounts($kept));

        Auth::login($kept);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
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

        self::assertSame($this->eachTableHolding(1), $this->recordCounts($user));
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

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($identity));
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

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($identity));
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
