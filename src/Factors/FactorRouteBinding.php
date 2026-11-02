<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;

/**
 * Holds what a factor model's route binding finds to the caller, for
 * `Concerns\ResolvesFactorRouteBinding`.
 *
 * Nobody served finds nothing, with no query. Otherwise the model's own lookup
 * runs on the write connection, and what it finds must be an instance of the
 * model and owned by the caller exactly, so a replica cannot lag behind a
 * removal and a case-insensitive collation cannot match another owner. A miss
 * is `null`. A database failure and a pending credential the resolver refuses
 * propagate: neither is a missing factor.
 *
 * Stateless: the caller is resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorRouteBinding
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,
    ) {}

    /**
     * What the lookup finds, when the caller owns it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $model
     * @param  \Closure(): mixed  $lookup
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     *
     * @param-immediately-invoked-callable $lookup
     */
    public function resolve(EloquentFactor&Model $model, \Closure $lookup): ?Model
    {
        $identity = $this->callers->forFactorBinding()?->identity;
        $key      = $identity?->getAuthIdentifier();

        if ($identity === null || (!is_string($key) && !is_int($key))) {
            return null;
        }

        $found = self::find($model, $lookup);

        return $found instanceof $model && FactorOwnerColumns::owns($found, CurrentIdentity::typeOf($identity), (string) $key) ? $found : null;
    }

    /**
     * Run the lookup on the write connection, its miss as `null`: Eloquent's
     * own lookup throws for a key that cannot be one of the model's.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $model
     * @param  \Closure(): mixed  $lookup
     * @return mixed
     *
     * @param-immediately-invoked-callable $lookup
     */
    private static function find(EloquentFactor&Model $model, \Closure $lookup): mixed
    {
        try {
            return WriteConnection::during($model, $lookup);
        } catch (ModelNotFoundException) { // @phpstan-ignore catch.neverThrown
            return null;
        }
    }
}
