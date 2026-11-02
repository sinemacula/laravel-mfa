<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * A guard holding a user arranged beforehand, as a guard with a context of its
 * own does, that records each `setUser()` it is asked for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingGuard implements Guard
{
    use GuardHelpers;

    /** @var list<\Illuminate\Contracts\Auth\Authenticatable> The users set, oldest first. */
    public array $set = [];

    /**
     * The user arranged.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function user(): ?Authenticatable
    {
        return $this->user;
    }

    /**
     * Validate nothing.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * Hold the user and note the call.
     *
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
     * Hold a user without noting it, as the guard's own helper arranges one.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function arrange(Authenticatable $user): void
    {
        $this->user = $user;
    }
}
