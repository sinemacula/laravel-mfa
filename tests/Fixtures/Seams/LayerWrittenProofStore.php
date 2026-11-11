<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * A store whose proofs and sign-ins only an authentication layer writes,
 * through `write()`, `signOut()` and `enrol()`. A proof naming a factor counts
 * only while the identity holds that factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LayerWrittenProofStore implements ProofStore
{
    /** @var array<string, list<\SineMacula\Laravel\Mfa\Proofs\Proof>> Proofs by sign-in. */
    private array $rows = [];

    /** @var array<string, string> Current sign-in by identity slot and application. */
    private array $current = [];

    /** @var list<string> */
    private array $factors = [];

    /**
     * @return string
     */
    public function signIn(): string
    {
        $session = 'layer-' . (count($this->rows) + 1);

        $this->rows[$session] = [];

        return $session;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    public function write(Proof $proof): void
    {
        $this->rows[$proof->binding->sessionId][] = $proof;
    }

    /**
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
     * @return string
     */
    public function enrol(): string
    {
        $factor = 'factor-' . (count($this->factors) + 1);

        $this->factors[] = $factor;

        return $factor;
    }

    /**
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
     * Keeps nothing, since the layer already holds a proof of the current
     * sign-in, and refuses any other.
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
     * The layer ends a sign-in before the package is told.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        // Already ended by the layer.
    }

    /**
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
