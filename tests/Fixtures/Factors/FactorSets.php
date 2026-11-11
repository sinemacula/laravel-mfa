<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * An identity's factors as the factor state transaction hands them over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorSets
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  ...$factors
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     */
    public static function of(EloquentFactor&Model ...$factors): Collection
    {
        return new Collection(array_values($factors));
    }

    /**
     * @param  ?string  $ownerKey
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     */
    public static function stored(?string $ownerKey = null): Collection
    {
        $query = Factor::query();

        if ($ownerKey !== null) {
            $query->where('authenticatable_id', $ownerKey);
        }

        return self::of(...$query->get()->all());
    }
}
