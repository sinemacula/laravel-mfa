<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use Tests\Fixtures\NonEloquentIdentity;
use Tests\Fixtures\NonScalarIdentifierUser;
use Tests\Fixtures\SecondaryUser;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `FactorStateCache`: values are resolved once per identity and key,
 * kept apart between identities, and cleared per identity or entirely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorStateCache::class)]
final class FactorStateCacheTest extends TestCase
{
    /** @var array<string, int> How many times each value was resolved. */
    private array $resolutions = [];

    /**
     * A value is resolved once and then served from the cache.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRemembersAValueOnceResolved(): void
    {
        $cache = $this->cache();
        $user  = $this->user(1);

        self::assertSame('setup:1', $this->read($cache, $user, 'setup', 'setup:1'));
        self::assertSame('setup:1', $this->read($cache, $user, 'setup', 'setup:2'));
        self::assertSame(1, $this->resolutions['setup:1']);
        self::assertArrayNotHasKey('setup:2', $this->resolutions);
    }

    /**
     * Each key of an identity is resolved on its own.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testKeepsKeysApart(): void
    {
        $cache = $this->cache();
        $user  = $this->user(1);

        self::assertSame('setup', $this->read($cache, $user, 'setup', 'setup'));
        self::assertSame('factors', $this->read($cache, $user, 'factors', 'factors'));
    }

    /**
     * Two identities of one type are kept apart by their identifier.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testKeepsIdentitiesOfOneTypeApart(): void
    {
        $cache = $this->cache();

        self::assertSame('one', $this->read($cache, $this->user(1), 'setup', 'one'));
        self::assertSame('two', $this->read($cache, $this->user(2), 'setup', 'two'));
    }

    /**
     * Two identities of different types with the same identifier are kept apart
     * by their type.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testKeepsIdentitiesOfDifferentTypesApart(): void
    {
        $cache     = $this->cache();
        $secondary = new SecondaryUser;

        $secondary->setAttribute('id', 1);

        self::assertSame('user', $this->read($cache, $this->user(1), 'setup', 'user'));
        self::assertSame('secondary', $this->read($cache, $secondary, 'setup', 'secondary'));
    }

    /**
     * An identity with a non-scalar identifier is cached and cleared without
     * failing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAcceptsAnIdentityWithANonScalarIdentifier(): void
    {
        $cache    = $this->cache();
        $identity = new NonScalarIdentifierUser;

        self::assertSame('value', $this->read($cache, $identity, 'setup', 'value'));

        $cache->clear($identity);

        self::assertSame('fresh', $this->read($cache, $identity, 'setup', 'fresh'));
    }

    /**
     * A non-Eloquent identity is cached under its class and identifier.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testCachesANonEloquentIdentity(): void
    {
        $cache = $this->cache();

        self::assertSame('a', $this->read($cache, new NonEloquentIdentity('a'), 'setup', 'a'));
        self::assertSame('b', $this->read($cache, new NonEloquentIdentity('b'), 'setup', 'b'));
        self::assertSame('a', $this->read($cache, new NonEloquentIdentity('a'), 'setup', 'c'));
    }

    /**
     * Clearing one identity forgets its values and keeps every other
     * identity's, including one whose identifier starts with the same digits.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClearingAnIdentityForgetsOnlyItsValues(): void
    {
        $cache = $this->cache();

        $this->read($cache, $this->user(1), 'setup', 'one');
        $this->read($cache, $this->user(1), 'factors', 'one-factors');
        $this->read($cache, $this->user(10), 'setup', 'ten');

        $cache->clear($this->user(1));

        self::assertSame('one-again', $this->read($cache, $this->user(1), 'setup', 'one-again'));
        self::assertSame('one-factors-again', $this->read($cache, $this->user(1), 'factors', 'one-factors-again'));
        self::assertSame('ten', $this->read($cache, $this->user(10), 'setup', 'ten-again'));
    }

    /**
     * Clearing without an identity forgets every value.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClearingWithoutAnIdentityForgetsEveryValue(): void
    {
        $cache = $this->cache();

        $this->read($cache, $this->user(1), 'setup', 'one');
        $this->read($cache, $this->user(2), 'setup', 'two');

        $cache->clear();

        self::assertSame('one-again', $this->read($cache, $this->user(1), 'setup', 'one-again'));
        self::assertSame('two-again', $this->read($cache, $this->user(2), 'setup', 'two-again'));
    }

    /**
     * Resolve a fresh cache from the container.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\FactorStateCache
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function cache(): FactorStateCache
    {
        return $this->container()->make(FactorStateCache::class);
    }

    /**
     * Build an unsaved test user with the given identifier.
     *
     * @param  int  $id
     * @return \Tests\Fixtures\TestUser
     */
    private function user(int $id): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', $id);

        return $user;
    }

    /**
     * Read the identity's value under the key, resolving it to the given value
     * (and counting the resolution) when it is not cached.
     *
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorStateCache  $cache
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  string  $key
     * @param  string  $value
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function read(FactorStateCache $cache, Authenticatable $identity, string $key, string $value): mixed
    {
        return $cache->remember($identity, $key, function () use ($value): string {
            $this->resolutions[$value] = ($this->resolutions[$value] ?? 0) + 1;

            return $value;
        });
    }
}
