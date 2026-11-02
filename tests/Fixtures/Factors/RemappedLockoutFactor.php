<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * An application's own factor model, not built on the shipped one, that keeps
 * its lockout deadline in a column of its own, `held_until`, and declares no
 * cast for it: the trait casts the column it is told holds the deadline.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
final class RemappedLockoutFactor extends Model implements EloquentFactor
{
    use ActsAsFactor, HasUlids;

    /** @var array<string> The attributes that are not mass assignable. */
    protected $guarded = [];

    /**
     * Name the package's factor table.
     *
     * @return string
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function getTable(): string
    {
        return TableNames::of(TableNames::FACTORS);
    }

    /**
     * Column name holding when the factor's temporary lockout ends.
     *
     * @return string
     */
    #[\Override]
    public function getLockedUntilName(): string
    {
        return 'held_until';
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'consecutive_failures' => 'integer',
            'disabled_at'          => 'datetime',
        ];
    }
}
