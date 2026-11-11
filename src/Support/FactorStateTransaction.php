<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Locks the identity state row, then its factors, so two factor state changes
 * never deadlock. The callback must recheck preconditions on what it is handed.
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
     * The factor model instance only names the class and its connection.
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
        return self::run(IdentityType::of($identity), self::keyOf($identity->getAuthIdentifier()), $factorModel, $callback);
    }

    /**
     * Read from the owner columns, so an owner that is not a model is locked
     * the same way.
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
     * For a record whose factor is gone, with no identity to hand.
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
     * The identity's factors without a lock, for checks before it and for
     * listings.
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

        return self::owned(WriteConnection::query($factorModel->newQuery()), IdentityType::of($identity), (string) $key, $factorModel);
    }

    /**
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

            IdentityStateRow::lock(new ProofOwner($type, $key), $connection);

            return $callback(self::owned($factorModel->newQuery()->lockForUpdate(), $type, $key, $factorModel));
        });
    }

    /**
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $query
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
     * Refuses a non-scalar key rather than collapse identities onto one lock.
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
