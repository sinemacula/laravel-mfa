<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A proof store one request binds in its own sandbox, built with the marker the
 * configuration of the application that built it holds, which notes what it is
 * asked to do, so a test can tell which application a listener reached.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigurationReadingProofStore implements ProofStore
{
    /** @var list<string> What was asked of the store, each with the marker it was built with. */
    public array $calls = [];

    /**
     * Constructor.
     *
     * @param  string  $marker
     */
    public function __construct(

        /** The marker the configuration held when the store was built. */
        private readonly string $marker,
    ) {}

    /**
     * Note the sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $this->calls[] = 'begin:' . $this->marker;
    }

    /**
     * There is no sign-in to answer with.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        return null;
    }

    /**
     * Nothing is kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    #[\Override]
    public function record(Proof $proof): void
    {
        $this->calls[] = 'record:' . $this->marker;
    }

    /**
     * There are no proofs to answer with.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        return [];
    }

    /**
     * Nothing is kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $this->calls[] = 'forgetFactor:' . $this->marker;
    }

    /**
     * Note the sign-out.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->calls[] = 'forget:' . $this->marker;
    }
}
