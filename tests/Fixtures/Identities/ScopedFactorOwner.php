<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A parent model with a factor relation, for scoped bindings such as
 * `/users/{user}/factors/{factor}`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 *
 * @internal
 */
final class ScopedFactorOwner extends Model
{
    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = ['email'];

    /**
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Mfa\Models\Factor, $this>
     */
    public function factors(): MorphMany
    {
        return $this->morphMany(Factor::class, 'authenticatable');
    }
}
