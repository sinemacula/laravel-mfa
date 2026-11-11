<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;

/**
 * Pins reads that decide a verification, lockout or ownership to the write
 * connection, since a lagging replica could pass a replay or miss a lockout.
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
     * Only this query is routed, not its eager loads.
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
     * Route every read on the model's connection to the writer, for queries the
     * package does not build. A failure is masked of the values it was given.
     *
     * @template TReturn
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @throws \Illuminate\Database\QueryException
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
        } catch (QueryException $failure) {
            QueryExceptionMask::mask($failure);

            throw $failure;
        } finally {
            $connection->useWriteConnectionWhenReading($previous);
        }
    }

    /**
     * Laravel has a setter for this mode but no getter.
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
