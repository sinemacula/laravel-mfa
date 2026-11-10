<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Grammar;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\GrammarExpression;
use Tests\TestCase;

/**
 * Unit tests for `GrammarExpression`: SQL written by the grammar that compiles
 * the statement holding it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrammarExpression::class)]
final class GrammarExpressionTest extends TestCase
{
    /**
     * The expression is what its writer gives for the grammar it is handed.
     *
     * @return void
     */
    public function testTheValueIsWrittenWithTheGrammarGiven(): void
    {
        $grammar    = DB::connection()->getQueryGrammar();
        $expression = new GrammarExpression(static fn (Grammar $given): string => $given->wrap('codes.id') . ' = ' . $given->quoteString('o\'clock'));

        self::assertSame($grammar->wrap('codes.id') . ' = ' . $grammar->quoteString('o\'clock'), $expression->getValue($grammar));
    }

    /**
     * A query compiles the expression with its own grammar, wrapping what it
     * names as the grammar does.
     *
     * @return void
     */
    public function testAQueryCompilesTheExpressionWithItsGrammar(): void
    {
        $count = new GrammarExpression(static fn (Grammar $grammar): string => "count({$grammar->wrap('mfa_codes.id')}) as remaining");
        $query = DB::connection()->table('mfa_codes')->select([$count]);

        self::assertSame('select count(' . $query->getGrammar()->wrap('mfa_codes.id') . ') as remaining from ' . $query->getGrammar()->wrapTable('mfa_codes'), $query->toSql());
    }
}
