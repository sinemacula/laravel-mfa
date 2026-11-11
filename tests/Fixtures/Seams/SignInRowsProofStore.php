<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * A store backed by an authentication layer's sessions: `begin()` only makes an
 * arranged sign-in current, and proofs stop counting when the layer voids them
 * whatever the verification generation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInRowsProofStore implements ProofStore
{
    /** @var array<string, list<\SineMacula\Laravel\Mfa\Proofs\Proof>> Proofs by sign-in. */
    private array $rows = [];

    /** @var array<string, string> Current sign-in by identity slot and application. */
    private array $current = [];

    /**
     * A sign-in holding its first factor proof, as signing in through the layer
     * leaves one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     */
    public function arrange(MultiFactorAuthenticatable $identity, string $application): string
    {
        $session = 'row-' . (count($this->rows) + 1);
        $owner   = ProofOwner::of($identity);

        $this->rows[$session] = [new Proof(
            kind      : ProofKind::FIRST_FACTOR,
            method    : 'password',
            channel   : new Channel(ChannelKind::PASSWORD),
            reference : null,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now(),
            binding   : new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::SIGN_IN),
            generation: 0,
        )];

        return $session;
    }

    /**
     * As the layer does on a reset.
     *
     * @return void
     */
    public function void(): void
    {
        $this->rows = array_map(static fn (): array => [], $this->rows);
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

        $this->rows[$proof->binding->sessionId][] = $proof;
    }

    /**
     * Ignores the generation the proofs were made under.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        return $this->currentSession($identity, $application) === $sessionId ? $this->rows[$sessionId] : [];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        foreach ($this->rows as $session => $proofs) {
            $this->rows[$session] = array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->reference !== $factorId));
        }
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        $key = self::key($identity, $application);

        if (isset($this->current[$key])) {
            unset($this->rows[$this->current[$key]]);
        }

        unset($this->current[$key]);
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
