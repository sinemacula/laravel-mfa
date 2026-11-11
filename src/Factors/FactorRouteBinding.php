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
 * Limits a factor route binding to the caller's own factors, for
 * `Concerns\ResolvesFactorRouteBinding`. Reads the write connection so a
 * replica cannot lag behind a removal, and matches the owner exactly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorRouteBinding
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** The request is read from it on every call. */
        private Container $container,

        /** Resolves who the caller is served as. */
        private CallerContextResolver $callers,
    ) {}

    /**
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
     * Eloquent's lookup throws for a key that cannot be the model's.
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
