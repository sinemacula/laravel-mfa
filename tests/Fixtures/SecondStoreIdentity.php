<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Second of two distinct Authenticatable classes used by the session-store
 * identity-class scoping test. Paired with `FirstStoreIdentity` to prove
 * that two different identity classes sharing an identifier do not collide
 * on a single verification slot in `SessionMfaVerificationStore`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SecondStoreIdentity implements Authenticatable
{
    /**
     * Constructor.
     *
     * @param  string  $identifier
     * @return void
     */
    public function __construct(

        /** Auth identifier reported by the fixture. */
        private readonly string $identifier,

    ) {}

    /**
     * Get the auth identifier name.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Get the auth identifier.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * Get the auth password name.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * Get the auth password — these fixtures never authenticate through the
     * password flow, so no password hash is needed.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        return 'unused-password';
    }

    /**
     * Get the remember token — remember-me state is never read or written
     * through these fixtures.
     *
     * @return string
     */
    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * Set the remember token — no-op for this fixture.
     *
     * @param  mixed  $value
     * @return void
     */
    #[\Override]
    public function setRememberToken(mixed $value): void {}

    /**
     * Get the remember token name.
     *
     * @return string
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }
}
