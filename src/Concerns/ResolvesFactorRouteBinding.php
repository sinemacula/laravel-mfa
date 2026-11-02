<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Factors\FactorRouteBinding;

/**
 * Route binding for a factor model: a bound factor is found only within the
 * caller's identity, from whichever credential the route uses, access or
 * pending. The lookup is the parent's own, so custom keys, soft deletes and a
 * base model's own binding keep working, read on the write connection and held
 * to the caller; what the caller does not own is a miss, which Laravel answers
 * with a `404`.
 *
 * It is an ownership rule, not permission to run the route: each helper the
 * route calls asks for its own pending action. The shipped model uses it; a
 * model of an application's own opts in beside `ActsAsFactor`. A custom key
 * must be unique across identities, since the first row found may be another
 * person's, which misses. A scoped child binding is its parent's lookup and
 * never reaches this trait, and a route that must bind other people's factors
 * uses `Route::bind()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Mfa\Contracts\EloquentFactor
 */
trait ResolvesFactorRouteBinding
{
    /**
     * Retrieve the model for a bound value, when the caller owns it.
     *
     * @param  mixed  $value
     * @param  mixed  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        return Container::getInstance()->make(FactorRouteBinding::class)->resolve($this, fn (): mixed => parent::resolveRouteBinding($value, $field));
    }

    /**
     * Retrieve the model for a bound value, soft-deleted ones included, when
     * the caller owns it.
     *
     * @param  mixed  $value
     * @param  mixed  $field
     * @return ?\Illuminate\Database\Eloquent\Model
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function resolveSoftDeletableRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        return Container::getInstance()->make(FactorRouteBinding::class)->resolve($this, fn (): mixed => parent::resolveSoftDeletableRouteBinding($value, $field));
    }
}
