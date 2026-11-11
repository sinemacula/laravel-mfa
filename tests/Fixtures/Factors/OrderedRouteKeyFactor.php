<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Orders its route binding lookup by primary key, so which of several rows
 * sharing a custom key is found first does not depend on the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OrderedRouteKeyFactor extends Factor
{
    /**
     * @param  mixed  $query
     * @param  mixed  $value
     * @param  ?string  $field
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function resolveRouteBindingQuery(mixed $query, mixed $value, mixed $field = null)
    {
        if (!$query instanceof Model && !$query instanceof Relation) {
            throw new \InvalidArgumentException('A bound value is looked up through a model or a relation.');
        }

        return parent::resolveRouteBindingQuery($query, $value, $field)->orderBy($this->getKeyName());
    }
}
