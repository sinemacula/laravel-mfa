<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * What a budget itself promises: it counts reads and writes exactly, only while
 * the path runs, and refuses a statement that is neither.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PerformanceContractTestCase::class)]
final class QueryBudgetContractTest extends PerformanceContractTestCase
{
    /**
     * A select is a read, and an insert, an update and a delete are writes.
     *
     * @return void
     */
    public function testReadsAndWritesAreCountedApart(): void
    {
        $result = $this->assertQueryBudget(1, 3, function (): string {
            DB::table('test_users')->insert(['email' => 'person@example.test']);
            DB::table('test_users')->update(['email' => 'other@example.test']);
            DB::table('test_users')->count();
            DB::table('test_users')->delete();

            return 'answered';
        });

        self::assertSame('answered', $result);
    }

    /**
     * A statement before or after the path is no part of its budget.
     *
     * @return void
     */
    public function testOnlyThePathIsCounted(): void
    {
        DB::table('test_users')->count();

        $this->assertQueryBudget(0, 0, static fn (): null => null);

        DB::table('test_users')->count();

        $this->assertQueryBudget(1, 0, static fn (): int => DB::table('test_users')->count());
    }

    /**
     * A count other than the budget fails, and names every statement made.
     *
     * @return void
     */
    public function testAnotherCountFailsAndListsTheStatements(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/1\. \[testing\] select count\(\*\)/');

        $this->assertQueryBudget(0, 0, static fn (): int => DB::table('test_users')->count());
    }

    /**
     * A statement that is neither a read nor a write fails whatever the counts.
     *
     * @return void
     */
    public function testAStatementNobodyClassifiedFails(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A statement is neither a read nor a write');

        $this->assertQueryBudget(0, 0, static fn (): bool => DB::statement('savepoint budget_contract'));
    }
}
