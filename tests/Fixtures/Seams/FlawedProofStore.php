<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Seams\Enums\ProofStoreFlaw;

/**
 * An in-memory proof store that keeps the contract except for the one flaw it
 * is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FlawedProofStore implements ProofStore
{
    /** @var array<string, array{session: ?string, application: ?string, begun: ?string, proofs: list<\SineMacula\Laravel\Mfa\Proofs\Proof>}> By identity slot. */
    private array $signIns = [];

    /** @var array<string, array<string, list<\SineMacula\Laravel\Mfa\Proofs\Proof>>> Proofs of replaced sign-ins, by slot and sign-in. */
    private array $replaced = [];

    /**
     * @param  \Tests\Fixtures\Seams\Enums\ProofStoreFlaw  $flaw
     */
    public function __construct(

        /** @var \Tests\Fixtures\Seams\Enums\ProofStoreFlaw */
        private readonly ProofStoreFlaw $flaw,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $slot     = ProofOwner::of($identity)->slot();
        $previous = $this->signIns[$slot] ?? null;

        if ($previous !== null && $previous['session'] !== null) {
            $this->replaced[$slot][$previous['session']] = $previous['proofs'];
        }

        $this->signIns[$slot] = ['session' => $sessionId, 'application' => $application, 'begun' => $sessionId, 'proofs' => []];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $session = $this->signIns[ProofOwner::of($identity)->slot()]['session'] ?? null;

        if ($session !== null && $this->flaw === ProofStoreFlaw::WRONG_SESSION) {
            return 'another-sign-in';
        }

        return $session;
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
        $owner = $this->flaw === ProofStoreFlaw::KEYS_BY_BINDING ? ProofOwner::boundBy($proof->binding) : ProofOwner::of($identity);
        $slot  = $owner->slot();

        $refusal = $this->refusal($owner, $proof);

        if ($refusal !== null) {
            $this->refuse($slot, $proof, $refusal);
        }

        if ($this->flaw === ProofStoreFlaw::DROPS_PROOFS) {
            return;
        }

        $this->signIns[$slot]['proofs'][] = $proof;
    }

    /**
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
        $slot    = ProofOwner::of($identity)->slot();
        $signIn  = $this->signIns[$slot] ?? null;
        $current = $signIn !== null && $sessionId === $signIn['session'];

        if (!$current && $this->flaw === ProofStoreFlaw::RETAINS_SIGN_INS && isset($this->replaced[$slot][$sessionId])) {
            return $this->replaced[$slot][$sessionId];
        }

        $readable = $current
            || $this->flaw === ProofStoreFlaw::READS_ANY_SIGN_IN
            || ($this->flaw === ProofStoreFlaw::KEEPS_PROOFS && $signIn !== null && $sessionId === $signIn['begun']);

        return $readable && $signIn !== null ? $signIn['proofs'] : [];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $slot = ProofOwner::of($identity)->slot();

        if (!isset($this->signIns[$slot])) {
            return;
        }

        $this->signIns[$slot]['proofs'] = array_values(array_filter($this->signIns[$slot]['proofs'], static fn (Proof $proof): bool => $proof->reference !== $factorId));
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
        $slot = ProofOwner::of($identity)->slot();

        if (!isset($this->signIns[$slot])) {
            return;
        }

        if ($this->flaw !== ProofStoreFlaw::KEEPS_SESSION) {
            $this->signIns[$slot]['session'] = null;
        }

        if ($this->flaw === ProofStoreFlaw::KEEPS_PROOFS) {
            return;
        }

        $this->signIns[$slot]['proofs'] = [];
    }

    /**
     * Why the owner's sign-in refuses the proof, or `null` when it takes it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return ?string
     */
    private function refusal(ProofOwner $owner, Proof $proof): ?string
    {
        $signIn = $this->signIns[$owner->slot()] ?? null;

        if ($signIn === null || $signIn['session'] === null) {
            return 'No sign-in is begun.';
        }

        if ($proof->binding->sessionId !== $signIn['session'] && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_SIGN_IN) {
            return 'The proof is bound to another sign-in.';
        }

        if (!$owner->owns($proof->binding) && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_IDENTITY) {
            return 'The proof is bound to another identity.';
        }

        return $proof->binding->application !== $signIn['application'] && $this->flaw !== ProofStoreFlaw::ACCEPTS_ANY_APPLICATION
            ? 'The proof is bound to another application.'
            : null;
    }

    /**
     * @param  string  $slot
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  string  $reason
     * @return never
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    private function refuse(string $slot, Proof $proof, string $reason): never
    {
        if (isset($this->signIns[$slot]) && $this->flaw === ProofStoreFlaw::KEEPS_A_REFUSED_PROOF) {
            $this->signIns[$slot]['proofs'][] = $proof;
        }

        $named = ProofOwner::boundBy($proof->binding)->slot();

        if (isset($this->signIns[$named]) && $this->flaw === ProofStoreFlaw::KEEPS_FOR_THE_NAMED_IDENTITY) {
            $this->signIns[$named]['proofs'][] = $proof;
        }

        if (isset($this->signIns[$named]) && $this->flaw === ProofStoreFlaw::ENDS_THE_NAMED_SIGN_IN) {
            $this->signIns[$named]['session'] = null;
        }

        if (isset($this->signIns[$slot]) && $this->flaw === ProofStoreFlaw::DESTROYS_ON_REFUSAL) {
            $this->signIns[$slot]['session'] = null;
            $this->signIns[$slot]['proofs']  = [];
        }

        throw new ProofRefusedException($reason);
    }
}
