<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\CountingProofs;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * A stateless guard's store: one sign-in per access token, and the current one
 * is the token the request carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TokenProofStore implements ProofStore
{
    /** @var array<string, list<\SineMacula\Laravel\Mfa\Proofs\Proof>> Proofs by identity, application and token. */
    private array $signIns = [];

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $this->signIns[self::key(ProofOwner::of($identity), $application, $sessionId)] = [];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $token = Container::getInstance()->make('request')->bearerToken();

        return $token !== null && isset($this->signIns[self::key(ProofOwner::of($identity), $application, $token)]) ? $token : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $owner   = ProofOwner::of($identity);
        $binding = $proof->binding;

        if (!$owner->owns($binding) || $this->currentSession($identity, $binding->application) !== $binding->sessionId) {
            throw new ProofRefusedException('The proof is not bound to the current token\'s sign-in.');
        }

        $this->signIns[self::key($owner, $binding->application, $binding->sessionId)][] = $proof;
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
        if ($this->currentSession($identity, $application) !== $sessionId) {
            return [];
        }

        return CountingProofs::of($identity, $application, $sessionId, $this->signIns[self::key(ProofOwner::of($identity), $application, $sessionId)]);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $owner = ProofOwner::of($identity);

        foreach ($this->signIns as $key => $proofs) {
            $this->signIns[$key] = array_values(array_filter($proofs, static fn (Proof $proof): bool => !$owner->owns($proof->binding) || $proof->reference !== $factorId));
        }
    }

    /**
     * Forgets the sign-in of the token the request carries.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        $token = $this->currentSession($identity, $application);

        if ($token === null) {
            return;
        }

        unset($this->signIns[self::key(ProofOwner::of($identity), $application, $token)]);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $application
     * @param  string  $token
     * @return string
     */
    private static function key(ProofOwner $owner, string $application, string $token): string
    {
        return implode("\0", [$owner->slot(), $application, $token]);
    }
}
