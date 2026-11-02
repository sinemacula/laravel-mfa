<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Finds the factor an attempt names among the identity's factors as stored
 * under the factor state lock, matched by id, so the attempt is counted on, and
 * verified against, the stored row rather than the instance its caller read.
 *
 * Only a factor that is both an `EloquentFactor` and a model keeps state of its
 * own on a row the lock covers; any other factor keeps none, and is never
 * found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockedFactors
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Determine whether the factor keeps state of its own, on a row the factor
     * state transaction locks.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return bool
     *
     * @phpstan-assert-if-true (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor) $factor
     */
    public static function keepsState(?Factor $factor): bool
    {
        return $factor instanceof EloquentFactor && $factor instanceof Model;
    }

    /**
     * The factor among the locked ones with the same id, or `null` when it
     * keeps no state of its own, has no usable id, is gone, or is not the
     * identity's.
     *
     * @formatter:off
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null
     *
     * @formatter:on
     */
    public static function find(?Factor $factor, Collection $factors): (EloquentFactor&Model)|null
    {
        $id = self::keepsState($factor) ? self::idOf($factor) : null;

        if ($id === null) {
            return null;
        }

        return $factors->first(static fn (EloquentFactor&Model $locked): bool => self::idOf($locked) === $id);
    }

    /**
     * The factor among those given with the id, or `null`: an id that is
     * neither a string nor an integer finds nothing. It is matched exactly, so
     * a custom model's key and a database's collation cannot make one id find
     * another.
     *
     * @formatter:off
     *
     * @param  mixed  $id
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null
     *
     * @formatter:on
     */
    public static function withId(mixed $id, Collection $factors): (EloquentFactor&Model)|null
    {
        if (!is_string($id) && !is_int($id)) {
            return null;
        }

        return $factors->first(static fn (EloquentFactor&Model $factor): bool => self::idOf($factor) === (string) $id);
    }

    /**
     * A factor's id as a string, or `null` when it is neither a non-empty
     * string nor an integer.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?string
     */
    public static function idOf(Factor $factor): ?string
    {
        $id = $factor->getFactorIdentifier();

        return (is_string($id) && $id !== '') || is_int($id) ? (string) $id : null;
    }
}
