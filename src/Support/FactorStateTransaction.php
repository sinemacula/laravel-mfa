<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * The one transaction, and the one lock order, of every change that depends on
 * an identity's whole factor state: confirming its first additional factor,
 * replacing its recovery codes, removing a factor, a reset, and a verification
 * racing any of them.
 *
 * The transaction runs on the storage connection (see `StorageConnection`),
 * where every package table lives, so the change commits or rolls back as one.
 * Inside it the identity's row in the identity states table is locked first,
 * inserted when the identity has none yet, and the identity's factors second,
 * read `FOR UPDATE` from the write connection. Every change takes the locks in
 * that order, so two changes for one identity never wait on each other in
 * opposite orders: the second waits for the first to commit, then finds what it
 * left. The callback is handed the factors as stored under the lock, so it
 * checks its preconditions again on them rather than on what its caller read
 * before (a factor a concurrent change removed is gone). They are matched to
 * the owner exactly: a database's collation may read and lock another owner's
 * too, differing only in case, and those are not handed over.
 *
 * The identity's row is locked by an insert that updates the existing row on a
 * conflict, which takes the row's exclusive lock in one statement on MySQL and
 * PostgreSQL, also when two first changes race to create it; SQLite serialises
 * its writers anyway. A factor model on another connection is refused before
 * the transaction opens, as two connections cannot commit as one.
 *
 * Calls the change makes to another package that must be atomic with it, such
 * as revoking sessions, belong inside the callback; an adapter whose own
 * storage is on another connection cannot be.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorStateTransaction
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Run the callback in a transaction on the storage connection, holding the
     * identity's state lock and then its factors' locks, and return what the
     * callback returns.
     *
     * The factor model is the configured one (an instance only names the class
     * and its connection); the callback is handed the identity's factors as
     * stored under the lock.
     *
     * @template TReturn
     *
     * @formatter:off
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factorModel
     * @param  \Closure(\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>): TReturn  $callback
     * @return TReturn
     *
     * @formatter:on
     *
     * @throws \Throwable
     *
     * @param-immediately-invoked-callable $callback
     */
    public static function forIdentity(Authenticatable $identity, EloquentFactor&Model $factorModel, \Closure $callback): mixed
    {
        return self::run(CurrentIdentity::typeOf($identity), self::keyOf($identity->getAuthIdentifier()), $factorModel, $callback);
    }

    /**
     * Run the callback as `forIdentity()` does, for the identity that owns the
     * factor, read from the factor's owner columns (see `FactorOwnerColumns`),
     * so an owner that is not an Eloquent model is locked as one that is.
     *
     * @template TReturn
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>): TReturn  $callback
     * @return TReturn
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     *
     * @param-immediately-invoked-callable $callback
     */
    public static function forFactor(EloquentFactor&Model $factor, \Closure $callback): mixed
    {
        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factor);

        $type = $factor->getAttribute($typeColumn);

        if (!is_string($type) || $type === '') {
            throw new UnsupportedIdentifierException('The factor names no owner type, so its owner\'s factor state cannot be locked.');
        }

        return self::run($type, self::keyOf($factor->getAttribute($keyColumn)), $factor, $callback);
    }

    /**
     * Run the callback as `forIdentity()` does, for the owner the type and key
     * name, so a record whose factor is gone can still be changed under its
     * owner's lock, with no identity object or factor to hand.
     *
     * @template TReturn
     *
     * @formatter:off
     *
     * @param  string  $type
     * @param  string  $key
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factorModel
     * @param  \Closure(\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>): TReturn  $callback
     * @return TReturn
     *
     * @formatter:on
     *
     * @throws \Throwable
     *
     * @param-immediately-invoked-callable $callback
     */
    public static function forOwner(string $type, string $key, EloquentFactor&Model $factorModel, \Closure $callback): mixed
    {
        return self::run($type, $key, $factorModel, $callback);
    }

    /**
     * The identity's factors as stored now, read from the write connection with
     * no lock and matched to the owner exactly, as the transaction matches
     * them: what a check made before the lock decides on, and what a listing
     * shows. An identity whose key is neither a string nor an integer holds
     * none.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factorModel
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @formatter:on
     */
    public static function snapshot(Authenticatable $identity, EloquentFactor&Model $factorModel): Collection
    {
        $key = $identity->getAuthIdentifier();

        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> $none */
        $none = $factorModel->newCollection();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            return $none;
        }

        return self::owned(WriteConnection::query($factorModel->newQuery()), CurrentIdentity::typeOf($identity), (string) $key, $factorModel);
    }

    /**
     * Open the transaction, take the locks in order and run the callback.
     *
     * @template TReturn
     *
     * @formatter:off
     *
     * @param  string  $type
     * @param  string  $key
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factorModel
     * @param  \Closure(\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>): TReturn  $callback
     * @return TReturn
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private static function run(string $type, string $key, EloquentFactor&Model $factorModel, \Closure $callback): mixed
    {
        StorageConnection::assertHolds($factorModel, 'mfa.factor.model');

        $connection = DB::connection(StorageConnection::name());

        return StorageTransaction::run(static function () use ($connection, $type, $key, $factorModel, $callback): mixed {

            self::lockIdentityState($connection, $type, $key);

            return $callback(self::owned($factorModel->newQuery()->lockForUpdate(), $type, $key, $factorModel));
        });
    }

    /**
     * What the query finds of the owner's factors, matched to it exactly.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $type
     * @param  string  $key
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factorModel
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @formatter:on
     */
    private static function owned(Builder $query, string $type, string $key, EloquentFactor&Model $factorModel): Collection
    {
        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factorModel);

        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> */
        return $query->where($typeColumn, $type)
            ->where($keyColumn, $key)
            ->get()
            ->filter(static fn (EloquentFactor&Model $factor): bool => FactorOwnerColumns::owns($factor, $type, $key))
            ->values();
    }

    /**
     * Lock the identity's state row until the transaction ends, creating it
     * when the identity has none yet.
     *
     * @param  \Illuminate\Database\ConnectionInterface  $connection
     * @param  string  $type
     * @param  string  $key
     * @return void
     */
    private static function lockIdentityState(ConnectionInterface $connection, string $type, string $key): void
    {
        $now = CarbonImmutable::now();

        $connection->table(TableNames::of(TableNames::IDENTITY_STATES))->upsert([[
            'id'                   => Str::lower((string) Str::ulid()),
            'authenticatable_type' => $type,
            'authenticatable_id'   => $key,
            'created_at'           => $now,
            'updated_at'           => $now,
        ]], ['authenticatable_type', 'authenticatable_id'], ['updated_at']);
    }

    /**
     * An owner key as it is stored on the owner columns: a string or an
     * integer, as a string. Anything else is refused rather than collapsing
     * distinct identities onto one lock.
     *
     * @param  mixed  $key
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function keyOf(mixed $key): string
    {
        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw new UnsupportedIdentifierException(sprintf('An owner key must be a non-empty string or an integer to lock its factor state; got [%s].', get_debug_type($key)));
        }

        return (string) $key;
    }
}
