<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A proof store whose sign-in is replaced just after the current one is first
 * read, as another request signing the identity in again would replace it,
 * while it keeps its records in the store it wraps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplacingProofStore implements ProofStore
{
    /** @var bool Whether the sign-in has been replaced yet. */
    private bool $replaced = false;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\ProofStore): void  $replace
     */
    public function __construct(

        /** The store the records are kept in. */
        private readonly ProofStore $store,

        /** Replaces the sign-in in the wrapped store, once. */
        private readonly \Closure $replace,
    ) {}

    /**
     * Begin the sign-in.
     *
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
     * The wrapped store's answer, after which the sign-in is replaced the first
     * time.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $current = $this->store->currentSession($identity, $application);

        if (!$this->replaced) {
            $this->replaced = true;

            ($this->replace)($this->store);
        }

        return $current;
    }

    /**
     * Record the identity's proof.
     *
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
        $this->store->record($identity, $proof);
    }

    /**
     * The proofs of the sign-in named, as the wrapped store reads them.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        return $this->store->proofs($identity, $application, $sessionId);
    }

    /**
     * Forget the factor's proofs.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $this->store->forgetFactor($identity, $factorId);
    }

    /**
     * Forget the sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->store->forget($identity, $application);
    }
}
