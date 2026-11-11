<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Answers another sign-in from a given read on, as a store shows another
 * request's write, while keeping its records in the store it wraps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InterruptingProofStore implements ProofStore
{
    /** @var int */
    private int $reads = 0;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  int  $readsBefore
     * @param  ?string  $next
     * @param  bool  $refusesRecords
     */
    public function __construct(

        /** Keeps the records. */
        private readonly ProofStore $store,

        /** How many reads answer as the wrapped store does. */
        private readonly int $readsBefore = 1,

        /** Answered by every later read. */
        private readonly ?string $next = 'sign-in-b',

        /** Whether every proof is refused. */
        private readonly bool $refusesRecords = false,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $this->store->begin($identity, $application, $sessionId);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        return ++$this->reads > $this->readsBefore ? $this->next : $this->store->currentSession($identity, $application);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        if ($this->refusesRecords) {
            throw new ProofRefusedException('The store refused the proof.');
        }

        $this->store->record($identity, $proof);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        return $this->store->proofs($identity, $application, $sessionId);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $this->store->forgetFactor($identity, $factorId);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->store->forget($identity, $application);
    }
}
