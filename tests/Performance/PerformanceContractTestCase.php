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
 * Exact read and write counts, since an upper bound would hide a statement that
 * went away; an unclassified statement fails rather than counting as either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    use RefreshDatabase;

    /** @var string */
    private const string NOW = '2026-11-01 12:00:00';

    /** @var list<array{connection: string, sql: string}> */
    private array $statements = [];

    /** @var bool */
    private bool $capturing = false;

    /**
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
