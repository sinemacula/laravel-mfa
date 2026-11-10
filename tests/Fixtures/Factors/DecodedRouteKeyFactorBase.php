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
 * A base factor model with a route binding of its own, as a model decoding a
 * hashed route key has: the value in a URL is encoded, and the value `stranger`
 * finds a model of another class altogether.
 *
 * The class-level suppression is for one method: the model-behaviour rule
 * reports a trait's public methods at the class that imports them, and its list
 * of framework hooks does not include Eloquent's trait initialiser,
 * `initializeActsAsFactor()`, which only sets casts.
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

    /** @var string The value that finds a model of another class. */
    public const string STRANGER = 'stranger';

    /**
     * Name the package's factor table.
     *
     * @return string
     */
    #[\Override]
    public function getTable(): string
    {
        return TableNames::of(TableNames::FACTORS);
    }

    /**
     * Decode the value, and look the factor up by what it decodes to.
     *
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
