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
        $lookup = fn (): mixed => $this->isNonIntegerKey($value, $field, 'resolveRouteBinding') ? null : parent::resolveRouteBinding($value, $field);

        return Container::getInstance()->make(FactorRouteBinding::class)->resolve($this, $lookup);
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
        $lookup = fn (): mixed => $this->isNonIntegerKey($value, $field, 'resolveSoftDeletableRouteBinding') ? null : parent::resolveSoftDeletableRouteBinding($value, $field);

        return Container::getInstance()->make(FactorRouteBinding::class)->resolve($this, $lookup);
    }

    /**
     * PostgreSQL fails comparing an integer key with a non-integer string. A
     * parent's own binding may decode the value, so it is left to that.
     *
     * @param  mixed  $value
     * @param  mixed  $field
     * @param  string  $method
     * @return bool
     */
    private function isNonIntegerKey(mixed $value, mixed $field, string $method): bool
    {
        return ($field ?? $this->getRouteKeyName()) === $this->getKeyName()
            && in_array($this->getKeyType(), ['int', 'integer'], true)
            && filter_var($value, FILTER_VALIDATE_INT)                === false
            && (new \ReflectionMethod(parent::class, $method))->class === Model::class;
    }
}
