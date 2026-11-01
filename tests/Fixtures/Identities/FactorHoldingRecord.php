<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;

/**
 * A model that uses the `HasFactors` trait without being an identity, stored in
 * the test users table, so deleting it shows the trait forgets nothing for a
 * model that cannot sign in.
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
