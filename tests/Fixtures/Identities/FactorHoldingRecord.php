<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;

/**
 * Uses `HasFactors` without being an identity, so deleting it shows the trait
 * forgets nothing for a model that cannot sign in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
final class FactorHoldingRecord extends Model
{
    use HasFactors;

    /** @var string|null */
    protected $table = 'test_users';
}
