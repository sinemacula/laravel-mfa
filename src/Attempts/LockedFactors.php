<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Matches a factor to its row as locked, so attempts count against the stored
 * state rather than the caller's copy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockedFactors
{
    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
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
     * Matched exactly, so a custom key or database collation cannot make one id
     * find another.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?string
     */
    public static function idOf(Factor $factor): ?string
    {
        $id = $factor->getFactorIdentifier();

        return (is_string($id) && $id !== '') || is_int($id) ? (string) $id : null;
    }
}
