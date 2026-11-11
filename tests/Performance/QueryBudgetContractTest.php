<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;

/**
 * Tests the budget itself, so it covers none of the package's source.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class QueryBudgetContractTest extends PerformanceContractTestCase
{
    /**
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
     * @return void
     */
    public function testAnotherCountFailsAndListsTheStatements(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/1\. \[testing\] select count\(\*\)/');

        $this->assertQueryBudget(0, 0, static fn (): int => DB::table('test_users')->count());
    }

    /**
     * @return void
     */
    public function testAStatementNobodyClassifiedFails(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A statement is neither a read nor a write');

        $this->assertQueryBudget(0, 0, static fn (): bool => DB::statement('savepoint budget_contract'));
    }
}
