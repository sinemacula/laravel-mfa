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
     * @return bool
     */
    public function check(): bool
    {
        return true;
    }

    /**
     * @return bool
     */
    public function guest(): bool
    {
        return false;
    }

    /**
     * @return \Tests\Fixtures\TestUser
     */
    public function user(): TestUser
    {
        return $this->resolved;
    }

    /**
     * @return int
     */
    public function id(): int
    {
        return $this->resolved->id;
    }

    /**
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        return true;
    }

    /**
     * @return bool
     */
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
    public function setUser(Authenticatable $user): self
    {
        return $this;
    }
}
