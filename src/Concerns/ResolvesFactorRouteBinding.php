<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Factors\FactorRouteBinding;

/**
 * Binds a factor only within the caller's identity, by access or pending
 * credential, so any other is a `404`. It wraps the parent's lookup, read on
 * the write connection. Ownership is not permission: each helper still checks
 * its own pending action. A custom key must be unique across identities.
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
