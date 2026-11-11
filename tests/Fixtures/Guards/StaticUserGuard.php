<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Tests\Fixtures\Identities\TestUser;

/**
 * A token-style guard that returns a pre-bound `TestUser`, as Sanctum and
 * Passport resolve one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StaticUserGuard implements Guard
{
    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $resolved
     * @return void
     */
    public function __construct(

        /** @var \Tests\Fixtures\Identities\TestUser */
        private readonly TestUser $resolved,
    ) {}

    /**
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
     * @return \Tests\Fixtures\Identities\TestUser
     */
    #[\Override]
    public function user(): TestUser
    {
        return $this->resolved;
    }

    /**
     * @return int
     */
    #[\Override]
    public function id(): int
    {
        return $this->resolved->id;
    }

    /**
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(array $credentials = []): bool
    {
        return true;
    }

    /**
     * @return bool
     */
    #[\Override]
    public function hasUser(): bool
    {
        return true;
    }

    /**
     * The identity is bound at construction.
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
