<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use Tests\Fixtures\Factors\Concerns\ReportsUsableFactorDefaults;

/**
 * A custom driver's factor that is an Eloquent model implementing only the
 * `Factor` contract, not `EloquentFactor`: it keeps its row in the factor table
 * but no state the package locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainModelFactor extends Model implements Factor
{
    use HasUlids, ReportsUsableFactorDefaults;

    /** @var string|null The table the factor's row is kept in. */
    protected $table = 'mfa_factors';

    /** @var array<string> Every attribute may be filled. */
    protected $guarded = [];

    /**
     * Return the row's key.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * Return the factor's driver name.
     *
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        $type = $this->getAttribute('type');

        return is_string($type) ? $type : '';
    }

    /**
     * Return the factor's label (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return null;
    }

    /**
     * Return the factor's destination (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getDestination(): ?string
    {
        return null;
    }

    /**
     * Return the factor's secret (none).
     *
     * @return ?string
     */
    #[\Override]
    public function getSecret(): ?string
    {
        return null;
    }
}
