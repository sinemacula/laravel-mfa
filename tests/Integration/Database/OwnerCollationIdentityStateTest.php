<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Concerns\HashesOwner;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\GenericIdentity;
use Tests\Fixtures\Identities\UlidIdentity;
use Tests\Fixtures\Lifecycle\Concerns\HoldsIdentityRecords;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Owners whose keys differ only in case stay apart on a case-insensitive
 * collation: MySQL's on the suite's connection, NOCASE given to SQLite here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityStateRow::class)]
#[CoversClass(ForgetIdentity::class)]
#[CoversClass(FactorStateTransaction::class)]
#[CoversTrait(HashesOwner::class)]
#[CoversTrait(HasFactors::class)]
final class OwnerCollationIdentityStateTest extends TestCase
{
    use ArrangesVerification, HoldsIdentityRecords;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $connection = DB::connection(StorageConnection::name());

        if ($connection->getDriverName() !== 'sqlite') {
            return;
        }

        foreach ($this->recordTables() as $table) {

            /** @var list<string> $indexes */
            $indexes   = $connection->table('sqlite_master')->where('type', 'index')->where('tbl_name', $table)->whereNotNull('sql')->pluck('sql')->all();
            $statement = $connection->scalar('select sql from sqlite_master where type = ? and name = ?', ['table', $table]);

            self::assertIsString($statement);

            $connection->statement(sprintf('drop table "%s"', $table));
            $connection->statement(preg_replace('/"(authenticatable_type|authenticatable_id)" varchar not null/', '$0 collate nocase', $statement) ?? $statement);

            foreach ($indexes as $index) {
                $connection->statement($index);
            }
        }
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneOwnersLockoutResetAndObligationLeaveTheOtherAlone(): void
    {
        config()->set('mfa.attempts.identity_limit', 2);

        $locked = new GenericIdentity('ab12Cd');
        $other  = new GenericIdentity('AB12CD');
        $mine   = $this->authenticatorAppOf($locked);
        $theirs = $this->authenticatorAppOf($other);

        $this->signIn($other);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($theirs->id, AuthenticatorApp::code($theirs)))->isVerified());

        $this->signIn($locked);

        Mfa::verify(Callers::current(), Submission::factor($mine->id, AuthenticatorApp::code($mine, 5)));
        Mfa::verify(Callers::current(), Submission::factor($mine->id, AuthenticatorApp::code($mine, 5)));

        self::assertSame(FailureReason::LOCKED, Mfa::verify(Callers::current(), Submission::factor($mine->id, AuthenticatorApp::code($mine)))->reason);
        self::assertNull($this->container()->make(AttemptService::class)->lockout($other));

        Mfa::resetIdentity($locked, new Actor('admin', '9'), 'Lost device');

        self::assertSame(2, IdentityState::query()->count());
        self::assertTrue(ReenrollmentObligation::isRequired($locked));
        self::assertFalse(ReenrollmentObligation::isRequired($other));
        self::assertNotSame([], $this->container()->make(ProofStore::class)->proofs($other, self::APPLICATION, self::SESSION));
        self::assertNull($this->container()->make(AttemptService::class)->lockout($other));

        $this->signIn($other);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($theirs->id, AuthenticatorApp::code($theirs, 1)))->isVerified());
    }

    /**
     * @return void
     */
    public function testEachOwnerReadsOnlyItsOwnFactors(): void
    {
        $mine  = new GenericIdentity('ab12Cd');
        $other = new GenericIdentity('AB12CD');

        $this->authenticatorAppOf($mine);

        $theirs = $this->authenticatorAppOf($other, ['status' => 'pending']);

        $this->actingAs($other);

        self::assertSame([$theirs->id], array_map(static fn (FactorSummary $summary): string => $summary->id, Mfa::factors(Callers::current())));
        self::assertFalse($other->isMfaEnabled());
        self::assertTrue($mine->isMfaEnabled());
    }

    /**
     * @return void
     */
    public function testEachEloquentOwnerReadsOnlyItsOwnFactors(): void
    {
        $mine  = new UlidIdentity;
        $other = new UlidIdentity;

        $mine->setAttribute('id', '01jab12cd0000000000000000a');
        $other->setAttribute('id', '01JAB12CD0000000000000000A');

        $this->authenticatorAppOf($mine);

        $theirs = $this->authenticatorAppOf($other, ['status' => 'pending']);

        self::assertSame([$theirs->id], $other->authFactors()->pluck('id')->all());
        self::assertFalse($other->isMfaEnabled());
        self::assertTrue($mine->isMfaEnabled());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingOneOwnerKeepsTheOthersRecords(): void
    {
        $forgotten = new GenericIdentity('ab12Cd');
        $kept      = new GenericIdentity('AB12CD');

        $this->giveRecords($forgotten);
        $this->giveRecords($kept);

        Mfa::forgetIdentity($forgotten);

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($forgotten));
        self::assertSame($this->eachTableHolding(1), $this->recordCounts($kept));
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function authenticatorAppOf(Authenticatable $identity, array $attributes = []): Factor
    {
        return Factor::query()->create([
            ...$this->ownerOf($identity),
            'status'       => 'confirmed',
            'confirmed_at' => CarbonImmutable::now(),
            ...AuthenticatorApp::FACTOR,
            ...$attributes,
        ]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\GenericIdentity  $identity
     * @return void
     */
    private function signIn(GenericIdentity $identity): void
    {
        $this->actingAs($identity);
        $this->beginSignIn($identity);
    }
}
