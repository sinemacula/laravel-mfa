<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\TableNames;
use Tests\Fixtures\Identities\TestUser;

/**
 * A factor model that decodes its route key, as one with hashed keys does, and
 * finds a model of another class for `stranger`.
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
abstract class DecodedRouteKeyFactorBase extends Model implements EloquentFactor
{
    use ActsAsFactor, HasUlids;

    /** @var string Finds a model of another class. */
    public const string STRANGER = 'stranger';

    /**
     * @return string
     */
    #[\Override]
    public function getTable(): string
    {
        return TableNames::of(TableNames::FACTORS);
    }

    /**
     * @param  mixed  $value
     * @param  ?string  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        if ($value === self::STRANGER) {
            return new TestUser;
        }

        return parent::resolveRouteBinding(is_string($value) ? base64_decode($value, true) : $value, $field);
    }
}
