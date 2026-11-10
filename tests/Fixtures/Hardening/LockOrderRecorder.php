<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * One log of a flow's statements on the storage connection and its calls to the
 * session seams, in the order they happened, each statement with the outermost
 * transaction it ran in, read against the lock order every change shares:
 *
 * 1. the first package statement that locks or writes in a transaction is the
 *    owner's identity lock;
 * 2. a transaction locks one owner's identity row only;
 * 3. once a session seam has been called, the transaction locks and writes no
 *    package table.
 *
 * This is evidence of the order of statements, not of their contention, which
 * stays with the tests that run on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockOrderRecorder
{
    /** @var list<array{seam: string, transaction: int}|array{statement: string, bindings: array<int|string, mixed>, transaction: int}> The log, oldest first. */
    public array $log = [];

    /** @var int The outermost transactions begun so far. */
    private int $transactions = 0;

    /**
     * Start recording the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     */
    public function __construct(

        /** The storage connection. */
        private readonly Connection $connection,
    ) {
        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSqliteGrammar($connection));
        }

        Event::listen(TransactionBeginning::class, function (TransactionBeginning $event): void {

            if ($event->connection !== $this->connection || $this->connection->transactionLevel() !== 1) {
                return;
            }

            $this->transactions++;
        });

        $connection->beforeExecuting(function (string $query, array $bindings): void {
            $this->log[] = ['statement' => $query, 'bindings' => $bindings, 'transaction' => $this->current()];
        });
    }

    /**
     * Forget everything logged so far.
     *
     * @return void
     */
    public function start(): void
    {
        $this->log = [];
    }

    /**
     * Note that a session seam was called, or that a default seam of the
     * package's own has finished its own same-owner work.
     *
     * @param  string  $seam
     * @return void
     */
    public function seam(string $seam): void
    {
        $this->log[] = ['seam' => $seam, 'transaction' => $this->current()];
    }

    /**
     * How the log breaks the lock order, in words.
     *
     * @return list<string>
     */
    public function violations(): array
    {
        $found = [];

        foreach ($this->byTransaction() as $entries) {
            $found = [...$found, ...$this->violationsIn($entries)];
        }

        return $found;
    }

    /**
     * The seams called, oldest first.
     *
     * @return list<string>
     */
    public function seams(): array
    {
        $seams = [];

        foreach ($this->log as $entry) {

            if (!isset($entry['seam'])) {
                continue;
            }

            $seams[] = $entry['seam'];
        }

        return $seams;
    }

    /**
     * The statements logged that lock or write the table's rows.
     *
     * @param  string  $table
     * @return list<array{statement: string, bindings: array<int|string, mixed>, transaction: int}>
     */
    public function lockingOrWriting(string $table): array
    {
        $found = [];

        foreach ($this->log as $entry) {

            if (!isset($entry['statement']) || !self::locksOrWrites($entry['statement']) || !str_contains($entry['statement'], $table)) {
                continue;
            }

            $found[] = $entry;
        }

        return $found;
    }

    /**
     * The transaction a statement run now belongs to, or zero for none.
     *
     * @return int
     */
    private function current(): int
    {
        return $this->connection->transactionLevel() > 0 ? $this->transactions : 0;
    }

    /**
     * The log's entries of each outermost transaction.
     *
     * @return array<int, list<array{seam: string, transaction: int}|array{statement: string, bindings: array<int|string, mixed>, transaction: int}>>
     */
    private function byTransaction(): array
    {
        $transactions = [];

        foreach ($this->log as $entry) {

            if ($entry['transaction'] === 0) {
                continue;
            }

            $transactions[$entry['transaction']][] = $entry;
        }

        return $transactions;
    }

    /**
     * How one transaction's entries break the lock order.
     *
     * @param  list<array{seam: string, transaction: int}|array{statement: string, bindings: array<int|string, mixed>, transaction: int}>  $entries
     * @return list<string>
     */
    private function violationsIn(array $entries): array
    {
        $found  = [];
        $first  = true;
        $seamed = null;
        $owners = [];

        foreach ($entries as $entry) {

            if (isset($entry['seam'])) {
                $seamed ??= $entry['seam'];

                continue;
            }

            if (!self::locksOrWritesThePackage($entry['statement'])) {
                continue;
            }

            $found = [...$found, ...self::violationsOf($entry['statement'], $first, $seamed)];
            $first = false;

            if (!self::isIdentityLock($entry['statement'])) {
                continue;
            }

            $owners[] = json_encode(array_slice($entry['bindings'], 0, 2), JSON_THROW_ON_ERROR);
        }

        return count(array_unique($owners)) > 1
            ? [...$found, 'More than one owner\'s identity row is locked: ' . implode(', ', array_unique($owners))]
            : $found;
    }

    /**
     * How the statement breaks the lock order, given whether it is the first to
     * lock or write and the seam called before it, if any.
     *
     * @param  string  $statement
     * @param  bool  $first
     * @param  ?string  $seamed
     * @return list<string>
     */
    private static function violationsOf(string $statement, bool $first, ?string $seamed): array
    {
        $found = [];

        if ($first && !self::isIdentityLock($statement)) {
            $found[] = 'The first lock is not the identity lock: ' . $statement;
        }

        if ($seamed !== null) {
            $found[] = sprintf('A package table is locked or written after [%s]: %s', $seamed, $statement);
        }

        return $found;
    }

    /**
     * Whether the statement locks or writes one of the package's tables.
     *
     * @param  string  $statement
     * @return bool
     */
    private static function locksOrWritesThePackage(string $statement): bool
    {
        return self::locksOrWrites($statement) && self::namesAPackageTable($statement);
    }

    /**
     * Whether the statement locks or writes rows.
     *
     * @param  string  $statement
     * @return bool
     */
    private static function locksOrWrites(string $statement): bool
    {
        return preg_match('/^\s*(insert|update|delete)\b/i', $statement) === 1 || stripos($statement, 'for update') !== false;
    }

    /**
     * Whether the statement is the upsert that locks an identity's row.
     *
     * @param  string  $statement
     * @return bool
     */
    private static function isIdentityLock(string $statement): bool
    {
        return preg_match('/^\s*insert\b/i', $statement) === 1
            && str_contains($statement, TableNames::of(TableNames::IDENTITY_STATES))
            && preg_match('/on conflict|on duplicate key/i', $statement) === 1;
    }

    /**
     * Whether the statement names one of the package's tables.
     *
     * @param  string  $statement
     * @return bool
     */
    private static function namesAPackageTable(string $statement): bool
    {
        $tables = array_map(TableNames::of(...), array_keys(TableNames::DEFAULTS));

        return array_filter($tables, static fn (string $table): bool => str_contains($statement, $table)) !== [];
    }
}
