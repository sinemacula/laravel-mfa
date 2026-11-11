<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;

/**
 * A factor model's owner columns, read from a blank instance, since a stored
 * factor's relation needs the owner's class, which may not be a model or exist.
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
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return array{0: string, 1: string}
     */
    public static function of(EloquentFactor&Model $factor): array
    {
        $relation = $factor->newInstance()->authenticatable();

        return [$relation->getMorphType(), $relation->getForeignKeyName()];
    }

    /**
     * Exact, as a collation may match another owner differing only in case.
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
