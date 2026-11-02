<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Hardening\LockMarkingSqliteGrammar;
use Tests\TestCase;

/**
 * An association matches a passkey factor only when it belongs to the factor,
 * by its identifier as a string, to the factor's owner, and names the factor's
 * own credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyAssociations::class)]
final class PasskeyAssociationsTest extends TestCase
{
    /** @var string The owner's type. */
    private const string TYPE = 'App\Models\User';

    /** @var string The owner's key. */
    private const string KEY = '7';

    /** @var string The credential the factor and its association name. */
    private const string CREDENTIAL = 'Y3JlZGVudGlhbC0x';

    /**
     * A factor's own association matches it, whether its identifier is a string
     * or an integer.
     *
     * @return void
     */
    public function testTheFactorsOwnAssociationMatches(): void
    {
        self::assertTrue(PasskeyAssociations::matches($this->factor('factor-1'), $this->owner(), $this->association('factor-1')));
        self::assertTrue(PasskeyAssociations::matches($this->factor(5), $this->owner(), $this->association('5')));
    }

    /**
     * Another factor's association does not match, even with the same owner and
     * credential.
     *
     * @return void
     */
    public function testAnotherFactorsAssociationDoesNotMatch(): void
    {
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), $this->owner(), $this->association('factor-2')));
    }

    /**
     * A factor with no usable identifier matches nothing, even an association
     * whose factor is the empty string its identifier would cast to.
     *
     * @return void
     */
    public function testAFactorWithoutAnIdentifierMatchesNothing(): void
    {
        self::assertFalse(PasskeyAssociations::matches($this->factor(null), $this->owner(), $this->association('')));
    }

    /**
     * No association, another owner or another credential matches nothing.
     *
     * @return void
     */
    public function testNoAssociationOrAnotherOwnerOrCredentialMatchesNothing(): void
    {
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), $this->owner(), null));
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), new ProofOwner(self::TYPE, '8'), $this->association('factor-1')));
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), new ProofOwner('App\Models\Admin', self::KEY), $this->association('factor-1')));
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1', 'b3RoZXI'), $this->owner(), $this->association('factor-1')));
    }

    /**
     * The owner's association of the credential is found; nobody's, or another
     * owner's, is not, and a row whose digest matches but whose id differs is
     * not either.
     *
     * @return void
     */
    public function testAnOwnedCredentialIsOnlyTheOwnersOwn(): void
    {
        $this->association('factor-1')->save();

        $associations = new PasskeyAssociations;

        self::assertSame('factor-1', $associations->ownedCredential(self::CREDENTIAL, $this->owner())?->factor_id);
        self::assertNull($associations->ownedCredential('Y3JlZGVudGlhbC0y', $this->owner()));
        self::assertNull($associations->ownedCredential(self::CREDENTIAL, new ProofOwner(self::TYPE, '8')));
        self::assertNull($associations->ownedCredential(self::CREDENTIAL, new ProofOwner('App\Models\Admin', self::KEY)));

        PasskeyAssociation::query()->where('factor_id', 'factor-1')->toBase()->update(['credential_id_hash' => CredentialId::hash('Y3JlZGVudGlhbC0y')]);

        self::assertNull($associations->ownedCredential('Y3JlZGVudGlhbC0y', $this->owner()));
    }

    /**
     * Two owners who differ only in case stay apart on a database whose
     * collation compares them as equal.
     *
     * @return void
     */
    public function testAnOwnedCredentialIsComparedExactly(): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() !== 'sqlite') {
            self::markTestSkipped('The collation is changed through SQLite\'s own schema.');
        }

        $statement = $connection->scalar('select sql from sqlite_master where type = ? and name = ?', ['table', 'mfa_passkey_associations']);

        self::assertIsString($statement);

        $connection->statement('drop table "mfa_passkey_associations"');
        $connection->statement(preg_replace('/"(authenticatable_type|authenticatable_id)" varchar not null/', '$0 collate nocase', $statement) ?? $statement);

        $association = $this->association('factor-1');

        $association->authenticatable_id = 'owner-a';
        $association->save();

        $associations = new PasskeyAssociations;

        self::assertNull($associations->ownedCredential(self::CREDENTIAL, new ProofOwner(self::TYPE, 'OWNER-A')));
        self::assertNull($associations->ownedCredential(self::CREDENTIAL, new ProofOwner(strtoupper(self::TYPE), 'owner-a')));
        self::assertNotNull($associations->ownedCredential(self::CREDENTIAL, new ProofOwner(self::TYPE, 'owner-a')));
    }

    /**
     * A unique index refusing an association of a credential someone holds is
     * the conflict it looks like, and leaves the transaction it ran in usable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialAlreadyAssociatedIsRefusedInsideItsOwnSavepoint(): void
    {
        $this->association('factor-1')->save();

        $associations = new PasskeyAssociations;

        DB::transaction(function () use ($associations): void {

            try {
                $associations->associate($this->owner(), 'factor-2', self::CREDENTIAL);

                self::fail('The credential is associated already.');
            } catch (OperationRefusedException $refusal) {
                self::assertSame(FailureReason::CREDENTIAL_ASSOCIATED, $refusal->reason);
            }

            $associations->associate($this->owner(), 'factor-2', 'Y3JlZGVudGlhbC0y');
        });

        self::assertSame(2, PasskeyAssociation::query()->count());
    }

    /**
     * The credential is looked up again with a locking read, as a plain read in
     * a MySQL transaction reads its snapshot, which can miss the row that was
     * committed after it.
     *
     * @return void
     */
    public function testAConflictIsLookedUpAgainWithALockingRead(): void
    {
        $this->association('factor-1')->save();

        $connection = DB::connection();

        self::assertInstanceOf(Connection::class, $connection);

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSqliteGrammar($connection));
        }

        $statements = [];

        $connection->beforeExecuting(static function (string $query) use (&$statements): void {
            $statements[] = $query;
        });

        try {
            (new PasskeyAssociations)->associate($this->owner(), 'factor-2', self::CREDENTIAL);

            self::fail('The credential is associated already.');
        } catch (OperationRefusedException) {
            self::assertStringContainsStringIgnoringCase('for update', (string) end($statements));
        }
    }

    /**
     * Any other unique violation is a database error, not a domain conflict:
     * the factor is associated already, with another credential, so the
     * credential itself is found nowhere.
     *
     * @return void
     */
    public function testAnUnrelatedUniqueViolationIsThrown(): void
    {
        $this->association('factor-1')->save();

        $this->expectException(UniqueConstraintViolationException::class);

        (new PasskeyAssociations)->associate($this->owner(), 'factor-1', 'Y3JlZGVudGlhbC0y');
    }

    /**
     * A deadlock on the insert leaves a nested transaction as Laravel's
     * wrapper, which copied the query's message, with no credential id anywhere
     * in what can be read off it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeadlockOnTheInsertLeavesNoCredentialId(): void
    {
        $this->deadlockTheNextInsert(1);

        try {
            DB::transaction(fn (): PasskeyAssociation => (new PasskeyAssociations)->associate($this->owner(), 'factor-1', self::CREDENTIAL));

            self::fail('The deadlock must reach the caller.');
        } catch (DeadlockException $failure) {
            self::assertStringStartsWith('deadlock detected: SQLSTATE[40001]: driver error 1213', $failure->getMessage());
            self::assertInstanceOf(QueryException::class, $failure->getPrevious());
            $this->assertHoldsNoCredential($failure);
        }

        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * Once masked, the deadlock is still one to the transactions around it, so
     * each level hands it on rather than rolling back to a savepoint a MySQL
     * deadlock has discarded, and the application's own retry runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMaskedDeadlockIsStillADeadlockToTheTransactionsAroundIt(): void
    {
        $this->deadlockTheNextInsert(1);

        $attempts = 0;

        DB::transaction(function () use (&$attempts): void {

            $attempts++;

            DB::transaction(fn (): PasskeyAssociation => (new PasskeyAssociations)->associate($this->owner(), 'factor-1', self::CREDENTIAL));
        }, 2);

        self::assertSame(2, $attempts);
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame(1, PasskeyAssociation::query()->count());
    }

    /**
     * A model event cancelling the save is told apart from a conflict.
     *
     * @return void
     */
    public function testACanceledSaveIsThrown(): void
    {
        PasskeyAssociation::saving(static fn (): false => false);

        $this->expectException(WriteCancelledException::class);

        (new PasskeyAssociations)->associate($this->owner(), 'factor-1', self::CREDENTIAL);
    }

    /**
     * Fail the given number of inserts from now, as a driver reporting a
     * deadlock does, quoting what each bound.
     *
     * @param  int  $failures
     * @return void
     */
    private function deadlockTheNextInsert(int $failures): void
    {
        $connection = DB::connection();

        self::assertInstanceOf(Connection::class, $connection);

        $connection->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$failures): void {

            if ($failures === 0 || !str_starts_with($query, 'insert')) {
                return;
            }

            $failures--;

            $quoted = implode(', ', array_filter($bindings, is_string(...)));
            $driver = new \PDOException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock (' . $quoted . ')');

            $driver->errorInfo = ['40001', 1213, 'Deadlock found when trying to get lock (' . $quoted . ')'];

            (new \ReflectionProperty(\Exception::class, 'code'))->setValue($driver, '40001');

            throw new QueryException((string) $connection->getName(), $query, $bindings, $driver);
        });
    }

    /**
     * Assert no message, binding or driver text in the failure's chain holds
     * the credential id.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function assertHoldsNoCredential(\Throwable $failure): void
    {
        for ($current = $failure; $current !== null; $current = $current->getPrevious()) {

            self::assertStringNotContainsString(self::CREDENTIAL, $current->getMessage());

            if ($current instanceof QueryException) {
                self::assertSame([], $current->getBindings());
            }

            if (!$current instanceof \PDOException) {
                continue;
            }

            self::assertStringNotContainsString(self::CREDENTIAL, serialize($current->errorInfo));
        }
    }

    /**
     * A passkey factor with the identifier and credential given.
     *
     * @param  mixed  $identifier
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function factor(mixed $identifier, string $credential = self::CREDENTIAL): Factor
    {
        $factor = \Mockery::mock(Factor::class);

        $factor->shouldReceive('getFactorIdentifier')->andReturn($identifier);
        $factor->shouldReceive('getCredentialReference')->andReturn($credential);

        return $factor;
    }

    /**
     * The owner the associations are made for.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofOwner
     */
    private function owner(): ProofOwner
    {
        return new ProofOwner(self::TYPE, self::KEY);
    }

    /**
     * An unsaved association of the factor given with the owner's credential.
     *
     * @param  string  $factorId
     * @return \SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    private function association(string $factorId): PasskeyAssociation
    {
        return new PasskeyAssociation([
            'factor_id'            => $factorId,
            'authenticatable_type' => self::TYPE,
            'authenticatable_id'   => self::KEY,
            'credential_id_hash'   => hash('sha256', self::CREDENTIAL),
            'credential_id'        => self::CREDENTIAL,
        ]);
    }
}
