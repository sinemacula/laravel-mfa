<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model whose owner relation names its own columns, `owner_type` and
 * `owner_id`, as an application's own model may, so the package is shown to
 * find an identity's factors by the relation rather than by the shipped column
 * names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RemappedOwnerFactor extends Factor
{
    /**
     * The owning identity, through the remapped owner columns.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        // @phpstan-ignore return.type
        return $this->morphTo('owner', 'owner_type', 'owner_id');
    }
}
