<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * Records what it was asked to revoke, or throws when told to fail. When told
 * to judge the current session itself, it returns the given completion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSessionRevoker implements SessionRevoker
{
    /** @var list<string> Oldest first. */
    public array $calls = [];

    /** @var list<array{factor: string, session: string}> Oldest first. */
    public array $removals = [];

    /**
     * @param  bool  $fails
     * @param  bool  $judges
     * @param  ?object  $completion
     */
    public function __construct(

        /** Whether a revocation throws. */
        private readonly bool $fails = false,

        /** Whether it judges the current session again itself. */
        private readonly bool $judges = false,

        /** Returned when it judges the session. */
        private readonly ?object $completion = null,
    ) {}

    /**
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
