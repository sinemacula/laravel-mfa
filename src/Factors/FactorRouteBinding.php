<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use SineMacula\Laravel\Mfa\Support\IdentityType;

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
 * It is an edge, run while Laravel binds the route's parameters: the caller is
 * built from the request being served (`Context\CallerContext::fromRequest()`)
 * on every call, and nothing is served outside a request.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** The container the request being served is read from. */
        private Container $container,

        /** The resolver of who the caller is served as. */
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
        $request  = $this->container->bound('request') ? $this->container->make('request') : null;
        $identity = $request instanceof Request ? $this->callers->forFactorBinding(CallerContext::fromRequest($request, null, $this->container))?->identity : null;
        $key      = $identity?->getAuthIdentifier();

        if ($identity === null || (!is_string($key) && !is_int($key))) {
            return null;
        }

        $found = self::find($model, $lookup);

        return $found instanceof $model && FactorOwnerColumns::owns($found, IdentityType::of($identity), (string) $key) ? $found : null;
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
