<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;

/**
 * A raw expression written by the grammar that compiles the statement holding
 * it, for SQL that names configured tables or carries values the package
 * formats itself: the grammar wraps the identifiers and quotes the values, so
 * nothing reaches the SQL unescaped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrammarExpression implements Expression
{
    /**
     * Constructor.
     *
     * @param  \Closure(\Illuminate\Database\Grammar): string  $write
     */
    public function __construct(

        /** Writes the expression with the grammar it is given. */
        private \Closure $write,
    ) {}

    /**
     * Write the expression with the grammar compiling the statement.
     *
     * @param  \Illuminate\Database\Grammar  $grammar
     * @return string
     */
    #[\Override]
    public function getValue(Grammar $grammar): string
    {
        return ($this->write)($grammar);
    }
}
