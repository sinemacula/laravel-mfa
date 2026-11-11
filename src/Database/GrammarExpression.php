<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;

/**
 * A raw expression written by the statement's own grammar, so configured table
 * names and values are wrapped and quoted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrammarExpression implements Expression
{
    /**
     * @param  \Closure(\Illuminate\Database\Grammar): string  $write
     */
    public function __construct(

        /** Called with the compiling grammar. */
        private \Closure $write,
    ) {}

    /**
     * @param  \Illuminate\Database\Grammar  $grammar
     * @return string
     */
    #[\Override]
    public function getValue(Grammar $grammar): string
    {
        return ($this->write)($grammar);
    }
}
