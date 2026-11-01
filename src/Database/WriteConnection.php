<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Database\Query\Builder;

/**
 * Pins the package's reads to the write connection.
 *
 * Every read that decides a verification, a lockout or who owns a factor must
 * see the primary's current state. A read replica can lag behind a lockout just
 * applied, a code just consumed or a factor just removed, so a read served from
 * it could pass a replay or miss a lockout the primary already holds. Reads
 * made inside a factor state transaction already go to the writer (they lock
 * their rows); every other such read is routed through `query()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WriteConnection
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Route the supplied Eloquent builder, relation or query builder to the
     * write connection and return it for chaining.
     *
     * Only this query is routed: the eager loads of its results run as separate
     * queries without the flag.
     *
     * @template TBuilder of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TBuilder  $query
     * @return TBuilder
     */
    public static function query(Builder $query): Builder
    {
        $query->useWritePdo();

        return $query;
    }
}
