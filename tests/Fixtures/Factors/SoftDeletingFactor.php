<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A soft-deleting factor model, for a table given a `deleted_at` column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SoftDeletingFactor extends Factor
{
    use SoftDeletes;
}
