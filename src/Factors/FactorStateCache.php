<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * The per-request cache of an identity's factor state, so middleware stacks
 * calling `isSetup()` and `getFactors()` in sequence do not repeat the reads.
 *
 * Entries are keyed by the identity's type and identifier under the configured
 * `mfa.cache_prefix`, so two MFA-capable models with overlapping primary keys
 * (`User #1` and `Admin #1`) cannot collide on a single slot. Every change to
 * an identity's factors clears that identity's entries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorStateCache
{
    /** @var array<string, mixed> The cached values, by prefixed key. */
    private array $entries = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configuration is read from. */
        private readonly Container $container,
    ) {}

    /**
     * Return the identity's cached value under the key, resolving and caching
     * it on first use.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  string  $key
     * @param  \Closure(): mixed  $resolve
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function remember(Authenticatable $identity, string $key, \Closure $resolve): mixed
    {
        $cacheKey = $this->prefix($identity) . $key;

        if (!array_key_exists($cacheKey, $this->entries)) {
            $this->entries[$cacheKey] = $resolve();
        }

        return $this->entries[$cacheKey];
    }

    /**
     * Clear the cache.
     *
     * Optionally scope the clear to a specific identity. When no identity is
     * provided, the entire cache is flushed.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function clear(?Authenticatable $identity = null): void
    {
        if ($identity === null) {
            $this->entries = [];

            return;
        }

        $prefix = $this->prefix($identity);

        $this->entries = array_filter(
            $this->entries,
            static fn (string $key): bool => !str_starts_with($key, $prefix),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * Get the cache key prefix for the given identity.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function prefix(Authenticatable $identity): string
    {
        $config = $this->container->make('config');

        /** @var string $prefix */
        $prefix = $config->get('mfa.cache_prefix', 'mfa:');

        $identifier = $identity->getAuthIdentifier();

        $suffix = is_string($identifier) || is_int($identifier)
            ? (string) $identifier
            : '';

        return $prefix . CurrentIdentity::typeOf($identity) . ':' . $suffix . ':';
    }
}
