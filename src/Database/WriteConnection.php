<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;

/**
 * Pins the package's reads to the write connection.
 *
 * Every read that decides a verification, a lockout or who owns a factor must
 * see the primary's current state. A read replica can lag behind a lockout just
 * applied, a code just consumed or a factor just removed, so a read served from
 * it could pass a replay or miss a lockout the primary already holds. Reads
 * made inside a factor state transaction already go to the writer (they lock
 * their rows); every other such read is routed through `query()`, or `during()`
 * where the query is one the package does not build.
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

    /**
     * Run the callback with every read on the model's connection routed to the
     * write connection, its own eager loads included, and put the connection's
     * earlier mode back afterwards: for a query the package does not build,
     * such as Eloquent's route binding. A relation on another connection is not
     * routed.
     *
     * @template TReturn
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public static function during(Model $model, \Closure $callback): mixed
    {
        $connection = $model->getConnection();
        $previous   = self::readsOnWriteConnection($connection);

        $connection->useWriteConnectionWhenReading();

        try {
            return $callback();
        } finally {
            $connection->useWriteConnectionWhenReading($previous);
        }
    }

    /**
     * Whether the connection already routes reads to the write connection.
     * Laravel exposes a setter for this mode but no getter, so the flag is read
     * from the connection's own scope.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function readsOnWriteConnection(Connection $connection): bool
    {
        $read = \Closure::bind(
            static fn (Connection $bound): bool => $bound->readOnWriteConnection,
            null,
            Connection::class,
        );

        return $read($connection);
    }
}
