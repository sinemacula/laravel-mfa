<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A proof store standing in for one whose proofs and sign-ins an authentication
 * layer alone writes: `record()` keeps nothing it is given (a proof of the
 * current sign-in is one the layer already holds) and refuses any other,
 * `forget()` does nothing, since the layer ends a sign-in before the package is
 * told, and a proof naming a factor counts only while the identity holds that
 * factor. The layer's own writes are `write()`, `signOut()` and `enrol()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LayerWrittenProofStore implements ProofStore
{
    /** @var array<string, list<\SineMacula\Laravel\Mfa\Proofs\Proof>> The proofs of each sign-in the layer holds. */
    private array $rows = [];

    /** @var ?string The current sign-in. */
    private ?string $session = null;

    /** @var list<string> The factors the identity holds. */
    private array $factors = [];

    /**
     * Sign the identity in through the layer, and return the sign-in's id.
     *
     * @return string
     */
    public function signIn(): string
    {
        $session = 'layer-' . (count($this->rows) + 1);

        $this->rows[$session] = [];

        return $session;
    }

    /**
     * Record the proof through the layer.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    public function write(Proof $proof): void
    {
        $this->rows[$proof->binding->sessionId][] = $proof;
    }

    /**
     * End the current sign-in through the layer.
     *
     * @return void
     */
    public function signOut(): void
    {
        if ($this->session !== null) {
            unset($this->rows[$this->session]);
        }

        $this->session = null;
    }

    /**
     * Enrol a factor for the identity, and return its id.
     *
     * @return string
     */
    public function enrol(): string
    {
        $factor = 'factor-' . (count($this->factors) + 1);

        $this->factors[] = $factor;

        return $factor;
    }

    /**
     * Make the layer's sign-in current, refusing one it does not hold.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        if (!array_key_exists($sessionId, $this->rows)) {
            throw new \InvalidArgumentException('No such sign-in.');
        }

        $this->session = $sessionId;
    }

    /**
     * The current sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        return $this->session;
    }

    /**
     * Keep nothing: a proof of the current sign-in is one the layer already
     * holds, and any other is refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    #[\Override]
    public function record(Proof $proof): void
    {
        if ($this->session === null || $proof->binding->sessionId !== $this->session) {
            throw new ProofRefusedException('No such sign-in is current.');
        }
    }

    /**
     * The proofs of the current sign-in that name no factor, or one the
     * identity still holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        $proofs = $this->session === null ? [] : $this->rows[$this->session];

        return array_values(array_filter($proofs, fn (Proof $proof): bool => $proof->reference === null || in_array($proof->reference, $this->factors, true)));
    }

    /**
     * Stop counting the factor: the identity no longer holds it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $this->factors = array_values(array_diff($this->factors, [$factorId]));
    }

    /**
     * Do nothing: the layer ends a sign-in before the package is told.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        // The layer has already ended the sign-in.
    }
}
