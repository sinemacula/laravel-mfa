<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Tests\Fixtures\TestUser;

/**
 * Token-style `Guard` fixture that hands back a pre-bound `TestUser` — mimics
 * the lookup path Sanctum / Passport take.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class StaticUserGuard implements Guard
{
    /**
     * Capture the resolved identity once at construction.
     *
     * @param  \Tests\Fixtures\TestUser  $resolved
     * @return void
     */
    public function __construct(

        /** Resolved identity returned by the guard. */
        private readonly TestUser $resolved,
    ) {}

    /**
     * Report that the fixture always has an authenticated identity.
     *
     * @imperative
     *
     * @return bool
     */
    #[\Override]
    public function check(): bool
    {
        return true;
    }

    /**
     * Report that the fixture is never a guest.
     *
     * @imperative
     *
     * @return bool
     */
    #[\Override]
    public function guest(): bool
    {
        return false;
    }

    /**
     * Return the pre-bound test user identity.
     *
     * @return \Tests\Fixtures\TestUser
     */
    #[\Override]
    public function user(): TestUser
    {
        return $this->resolved;
    }

    /**
     * Return the bound identity's auth identifier.
     *
     * @return int
     */
    #[\Override]
    public function id(): int
    {
        return $this->resolved->id;
    }

    /**
     * Accept any credentials — the fixture has a single pre-bound identity.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(array $credentials = []): bool
    {
        return true;
    }

    /**
     * Report that the fixture always has a bound identity.
     *
     * @return bool
     */
    #[\Override]
    public function hasUser(): bool
    {
        return true;
    }

    /**
     * No-op — the fixture binds its identity at construction time.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return self
     */
    #[\Override]
    public function setUser(Authenticatable $user): self
    {
        return $this;
    }
}
