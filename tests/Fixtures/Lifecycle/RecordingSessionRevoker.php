<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * A session revoker that advances nothing and records what it was asked to do,
 * as an authentication layer's would, and throws when told to; told to judge
 * the current session itself, it says so, returning the completion given.
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

    /** @var list<array{factor: string, session: string}> The removals it was told of, oldest first. */
    public array $removals = [];

    /**
     * Constructor.
     *
     * @param  bool  $fails
     * @param  bool  $judges
     * @param  ?object  $completion
     */
    public function __construct(

        /** Whether a revocation throws. */
        private readonly bool $fails = false,

        /** Whether it judges the current session again itself. */
        private readonly bool $judges = false,

        /** What it returns for the caller when it judges the session. */
        private readonly ?object $completion = null,
    ) {}

    /**
     * Record the revocation of the other sessions for the factor's removal.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $application, string $session): RemovalRevocation
    {
        $this->revoked('others');

        $this->removals[] = ['factor' => $factorId, 'session' => $session];

        return $this->judges ? RemovalRevocation::judged($this->completion) : RemovalRevocation::othersEnded();
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
