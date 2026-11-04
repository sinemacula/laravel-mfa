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
 * A proof store standing in for one backed by an authentication layer's
 * sessions: a sign-in is arranged first, holding the first factor proved on
 * signing in, `begin()` only makes it current, and its proofs stop counting
 * when it voids them, not when the verification generation advances.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInRowsProofStore implements ProofStore
{
    /** @var array<string, list<\SineMacula\Laravel\Mfa\Proofs\Proof>> The proofs of each sign-in arranged, as rows an authentication layer holds. */
    private array $rows = [];

    /** @var ?string The current sign-in. */
    private ?string $session = null;

    /**
     * Arrange a sign-in, as signing in through the layer would, holding the
     * first factor proved on signing in, and return its id.
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
     * Void every proof, as the layer does on a reset.
     *
     * @return void
     */
    public function void(): void
    {
        $this->rows = array_map(static fn (): array => [], $this->rows);
    }

    /**
     * Make the arranged sign-in current, refusing one never arranged.
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
     * Keep a proof of the current sign-in, refusing any other.
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

        $this->rows[$this->session][] = $proof;
    }

    /**
     * The proofs of the current sign-in, whatever generation they were made
     * under.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        return $this->session === null ? [] : $this->rows[$this->session];
    }

    /**
     * Stop counting the proofs made with the factor.
     *
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
     * Forget the current sign-in and its proofs.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        if ($this->session !== null) {
            unset($this->rows[$this->session]);
        }

        $this->session = null;
    }
}
