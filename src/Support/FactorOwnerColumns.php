<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;

/**
 * The columns a factor model records its owner in: the owner's type and its
 * key.
 *
 * They are read from the owner relation of a blank instance of the factor's
 * class, never of the factor itself: on a stored factor, Eloquent builds the
 * relation from an instance of the stored owner's class, which an owner that is
 * not an Eloquent model (or whose class no longer exists) cannot be, and the
 * columns do not depend on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorOwnerColumns
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The owner's type column and key column of the factor's model, in that
     * order.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return array{0: string, 1: string}
     */
    public static function of(EloquentFactor&Model $factor): array
    {
        $relation = $factor->newInstance()->authenticatable();

        return [$relation->getMorphType(), $relation->getForeignKeyName()];
    }

    /**
     * Whether the factor's owner columns hold exactly the owner's type and key:
     * a database's collation may match another owner's too, differing only in
     * case.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $type
     * @param  string  $key
     * @return bool
     */
    public static function owns(EloquentFactor&Model $factor, string $type, string $key): bool
    {
        [$typeColumn, $keyColumn] = self::of($factor);

        $stored = $factor->getAttribute($keyColumn);

        return $factor->getAttribute($typeColumn) === $type && (is_string($stored) || is_int($stored)) && (string) $stored === $key;
    }
}
