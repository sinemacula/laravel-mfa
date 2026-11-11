<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;
use Tests\Fixtures\Hardening\Concerns\FlowCatalog;
use Tests\Fixtures\Hardening\FailsTheNthQuery;
use Tests\Fixtures\Hardening\ServerErrorAnswered;
use Tests\TestCase;

/**
 * Fails each statement of every flow in turn: a database failure is thrown or a
 * server error, never a refusal, and its transaction leaves nothing behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageTransaction::class)]
#[CoversClass(QueryExceptionMask::class)]
final class QueryFailureSweepTest extends TestCase
{
    use FlowCatalog;

    /** @var array<string, list<array<string, mixed>>> Tables when the outermost transaction began. */
    private array $atBegin = [];

    /** @var int Reports when the outermost transaction began. */
    private int $reportsAtBegin = 0;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->resetFlows();

        Event::listen(TransactionBeginning::class, function (TransactionBeginning $event): void {

            if ($event->connection->transactionLevel() !== 1) {
                return;
            }

            $this->atBegin        = $this->tables();
            $this->reportsAtBegin = count($this->reported);
        });
    }

    /**
     * PostgreSQL runs each migration in a transaction, so stop copying the
     * tables before they are dropped.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Event::forget(TransactionBeginning::class);

        parent::tearDown();
    }

    /**
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('flowNames')]
    public function testEveryStatementOfTheFlowFailsAsAServerError(string $flow): void
    {
        $this->sweep($flow, false);
    }

    /**
     * Laravel raises a deadlock in a nested transaction as its own wrapper.
     *
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('flowNames')]
    public function testEveryStatementOfTheFlowDeadlocksAsAServerError(string $flow): void
    {
        $this->sweep($flow, true);
    }

    /**
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('app.debug', false);
        $config->set('logging.default', 'null');
    }

    /**
     * Counts the healthy flow's statements, then reseeds and fails each one.
     *
     * @param  string  $flow
     * @param  bool  $deadlock
     * @return void
     */
    private function sweep(string $flow, bool $deadlock): void
    {
        $seed   = $this->flows()[$flow];
        $failer = new FailsTheNthQuery($this->storage());
        $act    = $seed();

        $failer->arm();

        self::assertTrue($act(), 'The healthy flow must reach its branch.');

        $statements = $failer->seen;

        self::assertGreaterThan(0, $statements);

        for ($statement = 1; $statement <= $statements; $statement++) {

            $failer->arm();
            $this->resetFlows();

            $act = $seed();

            $failer->arm($statement, $deadlock);

            $failure = $this->failureOf($act, $failer, $statement);

            self::assertTrue($failer->fired, sprintf('Statement %d of %d must have failed.', $statement, $statements));
            self::assertSame(0, $this->storage()->transactionLevel(), 'No transaction may be left open.');

            if ($deadlock && $failer->firedNested) {
                self::assertNotInstanceOf(QueryException::class, $failure, 'A deadlock in a nested transaction must leave as Laravel\'s wrapper.');
            }

            $this->assertItHoldsNothingItWasGiven($failure, $failer);

            if (!$failer->firedInTransaction) {
                continue;
            }

            $failed = $failer->failed;

            $failer->arm();

            self::assertSame($this->atBegin, $this->tables(), sprintf('Statement %d [%s] left a row changed.', $statement, $failed));
            self::assertCount($this->reportsAtBegin, $this->reported, 'A transaction that rolled back must report nothing.');
        }
    }

    /**
     * @param  \Closure(): bool  $act
     * @param  \Tests\Fixtures\Hardening\FailsTheNthQuery  $failer
     * @param  int  $statement
     * @return \Throwable
     */
    private function failureOf(\Closure $act, FailsTheNthQuery $failer, int $statement): \Throwable
    {
        try {
            $answer = $act();
        } catch (CodeDeliveryFailedException|DeadlockException|QueryException|ServerErrorAnswered $failure) {
            return $failure;
        }

        self::fail(sprintf('Statement %d [%s] failed, and the flow answered [%s] rather than failing.', $statement, $failer->failed, var_export($answer, true)));
    }

    /**
     * @param  \Throwable  $failure
     * @param  \Tests\Fixtures\Hardening\FailsTheNthQuery  $failer
     * @return void
     */
    private function assertItHoldsNothingItWasGiven(\Throwable $failure, FailsTheNthQuery $failer): void
    {
        for ($current = $failure; $current !== null; $current = $current->getPrevious()) {

            $readable = [$current->getMessage()];

            if ($current instanceof QueryException) {
                $readable = [...$readable, ...array_filter($current->getBindings(), is_string(...))];
            }

            if ($current instanceof \PDOException) {
                $readable = [...$readable, ...array_filter($current->errorInfo ?? [], is_string(...))];
            }

            foreach ($this->flowSecrets as $secret) {
                foreach ($readable as $value) {
                    self::assertStringNotContainsString($secret, $value, sprintf('A failure of [%s] held what the flow was given.', $failer->failed));
                }
            }
        }
    }

    /**
     * Reads the raw PDO so no statement is counted; address slots are left out
     * as they live outside the transaction.
     *
     * @return array<string, list<array<string, mixed>>>
     */
    private function tables(): array
    {
        $tables = [];

        foreach (array_keys(TableNames::DEFAULTS) as $block) {

            $table = TableNames::of($block);
            $query = $this->storage()->getPdo()->query(sprintf('select * from %s', $this->storage()->getQueryGrammar()->wrapTable($table)));

            self::assertInstanceOf(\PDOStatement::class, $query);

            /** @var list<array<string, mixed>> $rows */
            $rows = array_values(array_filter(
                $query->fetchAll(\PDO::FETCH_ASSOC),
                static fn (array $row): bool => ($row['scope'] ?? null) !== AttemptScope::IP->value,
            ));

            usort($rows, static fn (array $a, array $b): int => serialize($a) <=> serialize($b));

            $tables[$table] = $rows;
        }

        return $tables;
    }

    /**
     * @return \Illuminate\Database\Connection
     */
    private function storage(): Connection
    {
        $connection = DB::connection(StorageConnection::name());

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
