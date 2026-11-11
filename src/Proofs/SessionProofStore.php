<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;

/**
 * The default proof store, in the Laravel session; overlapping requests each
 * write it back whole, so only a generation advance revokes everywhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionProofStore implements ProofStore
{
    /** @var string Session key holding every record, full destinations included. */
    public const string SESSION_KEY = 'mfa.proofs';

    /** @var int Most proofs one sign-in keeps. */
    public const int LIMIT = 50;

    /**
     * @param  \Illuminate\Contracts\Session\Session  $session
     */
    public function __construct(

        /** Holds the records. */
        private Session $session,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        $this->write(ProofOwner::of($identity), $application, ['session' => self::sessionId($sessionId), 'proofs' => []]);
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
        return $this->read(ProofOwner::of($identity), $application)['session'] ?? null;
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
        $owner = ProofOwner::of($identity);

        if (!$owner->owns($proof->binding)) {
            throw new ProofRefusedException('The proof is not bound to the identity, so it cannot be recorded.');
        }

        $application = $proof->binding->application;
        $record      = $this->read($owner, $application);

        if ($record === null || $record['session'] !== $proof->binding->sessionId) {
            throw new ProofRefusedException('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.');
        }

        $record['proofs'][] = $proof->toArray();

        $this->write($owner, $application, ['session' => $record['session'], 'proofs' => self::bounded($record['proofs'])]);
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
        $record = $this->read(ProofOwner::of($identity), $application);

        if ($record === null || $record['session'] !== $sessionId) {
            return [];
        }

        $restored = array_filter(array_map(self::restore(...), $record['proofs']));

        return CountingProofs::of($identity, $application, $sessionId, $restored);
    }

    /**
     * Other sessions stop counting the factor's proofs only when the generation
     * advances.
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
        $owner = ProofOwner::of($identity);

        foreach (array_keys($this->owned($owner)) as $application) {

            $record = $this->read($owner, (string) $application);

            if ($record === null) {
                continue;
            }

            $kept = array_filter($record['proofs'], static fn (array $stored): bool => ($stored['reference'] ?? null) !== $factorId);

            $this->write($owner, (string) $application, ['session' => $record['session'], 'proofs' => array_values($kept)]);
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
        $slot    = ProofOwner::of($identity)->slot();
        $records = $this->records();
        $owned   = is_array($records[$slot] ?? null) ? $records[$slot] : [];

        unset($owned[$application]);

        if ($owned === []) {
            unset($records[$slot]);
        } else {
            $records[$slot] = $owned;
        }

        $this->session->put(self::SESSION_KEY, $records);
    }

    /**
     * @param  string  $sessionId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function sessionId(string $sessionId): string
    {
        if (trim($sessionId) === '') {
            throw new \InvalidArgumentException('The session id of a sign-in must not be blank.');
        }

        return $sessionId;
    }

    /**
     * `null` for a record that no longer reads back.
     *
     * @param  array<array-key, mixed>  $stored
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function restore(array $stored): ?Proof
    {
        try {
            return Proof::fromArray($stored);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Forget the earliest recorded beyond `LIMIT`, never the latest first
     * factor, so earlier first factors cannot crowd out an additional proof.
     *
     * @param  list<array<array-key, mixed>>  $proofs
     * @return list<array<array-key, mixed>>
     */
    private static function bounded(array $proofs): array
    {
        $firstFactor = null;

        foreach ($proofs as $position => $stored) {

            if (($stored['kind'] ?? null) !== ProofKind::FIRST_FACTOR->value) {
                continue;
            }

            $firstFactor = $position;
        }

        $excess = count($proofs) - self::LIMIT;

        foreach (array_keys($proofs) as $position) {

            if ($excess <= 0) {
                break;
            }

            if ($position === $firstFactor) {
                continue;
            }

            unset($proofs[$position]);

            $excess--;
        }

        return array_values($proofs);
    }

    /**
     * `null` when there is none or what is stored is malformed.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $application
     * @return ?array{session: string, proofs: list<array<array-key, mixed>>}
     */
    private function read(ProofOwner $owner, string $application): ?array
    {
        $record = $this->owned($owner)[$application] ?? null;

        if (!is_array($record)) {
            return null;
        }

        $session = $record['session'] ?? null;
        $stored  = $record['proofs']  ?? null;

        if (!is_string($session) || !is_array($stored)) {
            return null;
        }

        /** @var list<array<array-key, mixed>> $proofs */
        $proofs = array_values(array_filter($stored, is_array(...)));

        return ['session' => $session, 'proofs' => $proofs];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $application
     * @param  array{session: string, proofs: list<array<array-key, mixed>>}  $record
     * @return void
     */
    private function write(ProofOwner $owner, string $application, array $record): void
    {
        $records = $this->records();
        $owned   = $this->owned($owner);

        $owned[$application]     = $record;
        $records[$owner->slot()] = $owned;

        $this->session->put(self::SESSION_KEY, $records);
    }

    /**
     * Keyed by application.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return array<array-key, mixed>
     */
    private function owned(ProofOwner $owner): array
    {
        $owned = $this->records()[$owner->slot()] ?? null;

        return is_array($owned) ? $owned : [];
    }

    /**
     * Keyed by owner slot.
     *
     * @return array<array-key, mixed>
     */
    private function records(): array
    {
        $records = $this->session->get(self::SESSION_KEY);

        return is_array($records) ? $records : [];
    }
}
