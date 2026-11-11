<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * Holds a user arranged beforehand and records each `setUser()` call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingGuard implements Guard
{
    use GuardHelpers;

    /** @var list<\Illuminate\Contracts\Auth\Authenticatable> Oldest first. */
    public array $set = [];

    /**
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function user(): ?Authenticatable
    {
        return $this->user;
    }

    /**
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return self
     */
    #[\Override]
    public function setUser(Authenticatable $user): self
    {
        $this->set[] = $user;

        $this->user = $user;

        return $this;
    }

    /**
     * Holds a user without recording the call.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function arrange(Authenticatable $user): void
    {
        $this->user = $user;
    }
}
