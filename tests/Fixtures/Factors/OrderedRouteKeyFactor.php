<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * The shipped factor model with its route binding lookup ordered by primary
 * key, so which of several rows holding one custom key is found first does not
 * depend on how a database happens to return them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OrderedRouteKeyFactor extends Factor
{
    /**
     * Retrieve the model for a bound value, lowest primary key first.
     *
     * @param  mixed  $query
     * @param  mixed  $value
     * @param  mixed  $field
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function resolveRouteBindingQuery(mixed $query, mixed $value, mixed $field = null)
    {
        return parent::resolveRouteBindingQuery($query, $value, $field)->orderBy($this->getKeyName());
    }
}
