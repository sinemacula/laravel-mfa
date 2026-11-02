<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;

/**
 * A session revoker that advances nothing and records what it was asked to do,
 * as an authentication layer's would, and throws when told to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSessionRevoker implements SessionRevoker
{
    /** @var list<string> The calls made, oldest first. */
    public array $calls = [];

    /**
     * Constructor.
     *
     * @param  bool  $fails
     */
    public function __construct(

        /** Whether a revocation throws. */
        private readonly bool $fails = false,
    ) {}

    /**
     * Record the revocation of the other sessions.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function revokeOthers(MultiFactorAuthenticatable $identity): void
    {
        $this->revoked('others');
    }

    /**
     * Record the revocation of every session.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        $this->revoked('all');
    }

    /**
     * Record the call, or throw.
     *
     * @param  string  $call
     * @return void
     *
     * @throws \RuntimeException
     */
    private function revoked(string $call): void
    {
        if ($this->fails) {
            throw new \RuntimeException('The sessions could not be ended.');
        }

        $this->calls[] = $call;
    }
}
