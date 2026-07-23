<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * Custom `Guard` fixture that hands back a non-Eloquent `GenericUser` —
 * exercises the manager's non-Eloquent authenticatable short-circuit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class GenericUserGuard implements Guard
{
    /** @var \Illuminate\Auth\GenericUser */
    private readonly GenericUser $resolved;

    /**
     * Build the fixture identity once at construction.
     *
     * @return void
     */
    public function __construct()
    {
        $this->resolved = new GenericUser(['id' => 99, 'name' => 'Generic']);
    }

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
     * Return the pre-built non-Eloquent identity.
     *
     * @return \Illuminate\Auth\GenericUser
     */
    #[\Override]
    public function user(): GenericUser
    {
        return $this->resolved;
    }

    /**
     * Return the fixture identity's auth identifier.
     *
     * @return int
     */
    #[\Override]
    public function id(): int
    {
        return 99;
    }

    /**
     * Accept any credentials — the fixture has a single pre-built identity.
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
