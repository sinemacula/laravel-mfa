<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * A guard that returns a non-Eloquent `GenericUser`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GenericUserGuard implements Guard
{
    /** @var \Illuminate\Auth\GenericUser */
    private readonly GenericUser $resolved;

    /**
     * @return void
     */
    public function __construct()
    {
        $this->resolved = new GenericUser(['id' => 99, 'name' => 'Generic']);
    }

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
     * @return \Illuminate\Auth\GenericUser
     */
    #[\Override]
    public function user(): GenericUser
    {
        return $this->resolved;
    }

    /**
     * @return int
     */
    #[\Override]
    public function id(): int
    {
        return 99;
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
     * The identity is built at construction.
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
