<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

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

    /** @var array<string, string> Each identity's current sign-in on each application, by its slot and the application. */
    private array $current = [];

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
     * End every current sign-in through the layer.
     *
     * @return void
     */
    public function signOut(): void
    {
        foreach ($this->current as $session) {
            unset($this->rows[$session]);
        }

        $this->current = [];
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

        $this->current[self::key($identity, $application)] = $sessionId;
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
        return $this->current[self::key($identity, $application)] ?? null;
    }

    /**
     * Keep nothing: a proof of the identity's current sign-in is one the layer
     * already holds, and any other is refused.
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
        if (!$this->isOfTheCurrentSignIn($identity, $proof)) {
            throw new ProofRefusedException('No such sign-in is current.');
        }
    }

    /**
     * The proofs of the sign-in named, when it is the current one, that name no
     * factor, or one the identity still holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        $proofs = $this->currentSession($identity, $application) === $sessionId ? $this->rows[$sessionId] : [];

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

    /**
     * Whether the proof is the identity's, bound to the current sign-in on its
     * application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function isOfTheCurrentSignIn(MultiFactorAuthenticatable $identity, Proof $proof): bool
    {
        return ProofOwner::of($identity)->owns($proof->binding)
            && $proof->binding->sessionId === $this->currentSession($identity, $proof->binding->application);
    }

    /**
     * The key of the identity's current sign-in on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function key(MultiFactorAuthenticatable $identity, string $application): string
    {
        return ProofOwner::of($identity)->slot() . '#' . $application;
    }
}
