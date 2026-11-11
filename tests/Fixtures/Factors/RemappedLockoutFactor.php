<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * A factor model of its own that keeps its lockout deadline in `held_until`
 * with no casts, so the trait must cast the columns it is told about.
 *
 * The suppression is for the trait initialiser `initializeActsAsFactor()`,
 * which the model-behaviour rule does not know as a framework hook.
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

    /** @var array<string> */
    protected $guarded = [];

    /**
     * @return string
     */
    #[\Override]
    public function getTable(): string
    {
        return TableNames::of(TableNames::FACTORS);
    }

    /**
     * @return string
     */
    #[\Override]
    public function getLockedUntilName(): string
    {
        return 'held_until';
    }

    /**
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'consecutive_failures' => 'integer',
        ];
    }
}
