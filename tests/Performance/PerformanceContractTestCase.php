<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * Shared base for the query budgets: exact read and write counts for a path,
 * rather than wall-clock assertions, which would be flaky, or upper bounds,
 * which would hide a statement that went away and let a ledger comment drift.
 *
 * Statements are recorded from every connection, and only while the path under
 * test runs. A select is a read and an insert, an update or a delete is a
 * write; anything else fails the test, so a statement nobody has classified is
 * never counted silently as one or the other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    use RefreshDatabase;

    /** @var string The time every budget runs at. */
    private const string NOW = '2026-11-01 12:00:00';

    /** @var list<array{connection: string, sql: string}> The statements the path under test made. */
    private array $statements = [];

    /** @var bool Whether the path under test is running. */
    private bool $capturing = false;

    /**
     * Freeze both clocks and listen for statements.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(self::NOW);
        CarbonImmutable::setTestNow(self::NOW);

        DB::listen(function (QueryExecuted $query): void {

            if (!$this->capturing) {
                return;
            }

            $this->statements[] = ['connection' => $query->connectionName, 'sql' => $query->sql];
        });
    }

    /**
     * Release both clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Run the path and assert exactly how many reads and writes it made.
     *
     * @template TResult
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  callable(): TResult  $callback
     * @return TResult
     */
    protected function assertQueryBudget(int $reads, int $writes, callable $callback): mixed
    {
        $this->statements = [];
        $this->capturing  = true;

        try {
            $result = $callback();
        } finally {
            $this->capturing = false;
        }

        static::assertSame(['read' => $reads, 'write' => $writes], $this->counts(), "The path left its query budget.\n" . $this->listing());

        return $result;
    }

    /**
     * Whether the statement reads or writes, or null when it does neither.
     *
     * @param  string  $sql
     * @return ?string
     */
    private static function kindOf(string $sql): ?string
    {
        return match (strtolower(strtok(ltrim($sql), " \t\r\n(") ?: '')) {
            'select'                     => 'read',
            'insert', 'update', 'delete' => 'write',
            default                      => null,
        };
    }

    /**
     * How many reads and writes the path made, failing the test on a statement
     * that is neither.
     *
     * @return array{read: int, write: int}
     */
    private function counts(): array
    {
        $reads  = 0;
        $writes = 0;

        foreach ($this->statements as $statement) {

            $kind = self::kindOf($statement['sql']);

            if ($kind === null) {
                static::fail(sprintf("A statement is neither a read nor a write: [%s].\n%s", $statement['sql'], $this->listing()));
            }

            if ($kind === 'read') {
                $reads++;
            } else {
                $writes++;
            }
        }

        return ['read' => $reads, 'write' => $writes];
    }

    /**
     * Every statement the path made, in order, with its connection.
     *
     * @return string
     */
    private function listing(): string
    {
        $lines = [];

        foreach ($this->statements as $index => $statement) {
            $lines[] = sprintf('%d. [%s] %s', $index + 1, $statement['connection'], $statement['sql']);
        }

        return implode("\n", $lines);
    }
}
