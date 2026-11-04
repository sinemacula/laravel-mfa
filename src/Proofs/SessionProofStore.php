<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;

/**
 * The default proof store: each identity's current sign-in on each application
 * and the full records of its proofs, kept in the Laravel session under
 * `mfa.proofs`.
 *
 * A sign-in begins on Laravel's `Login` event, or through
 * `GuardHooks::signedIn()` for a guard that fires none, and ends on `Logout`,
 * `CurrentDeviceLogout` or `GuardHooks::signedOut()`; beginning one forgets the
 * proofs of the one before. Records are kept per identity, by its type and key,
 * and per application, so two identity types sharing a key never share one, and
 * signing in or out of one application leaves the identity's sign-in on another
 * alone. Every proof is read back against the identity, the application, the
 * sign-in and the identity's verification generation it is asked for.
 *
 * It fails closed. A proof bound to another sign-in, or to an application the
 * identity has not signed in to, is refused when it is recorded. When the
 * proofs are read, one is left out when it is bound to another identity,
 * application or sign-in, was made after now, was made under another
 * verification generation than the identity's current one, or cannot be read
 * back; an identity with no sign-in on the application has none.
 *
 * The records are bounded: a sign-in keeps at most 50 proofs, and recording
 * more forgets the earliest recorded, though never the latest first factor. The
 * session holds each channel's full destination, so it must be stored where the
 * application keeps its other session secrets.
 *
 * Like anything else kept in the Laravel session, the records are written back
 * whole when a request ends, so two overlapping requests on one session may
 * each save their own copy. Forgetting a factor's proofs therefore holds on the
 * current session only as far as its requests are serialised; advancing the
 * identity's verification generation is what stops a proof counting everywhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionProofStore implements ProofStore
{
    /** @var string The session key every identity's records are kept under. */
    public const string SESSION_KEY = 'mfa.proofs';

    /** @var int The most proofs one sign-in keeps. */
    public const int LIMIT = 50;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Session\Session  $session
     */
    public function __construct(

        /** The session the records are kept in. */
        private Session $session,
    ) {}

    /**
     * Begin a new sign-in for the identity on the application, forgetting every
     * proof of the one before.
     *
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
     * The session id of the identity's current sign-in on the application, or
     * `null` when it has none.
     *
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
     * Record a proof for its identity's current sign-in on its application,
     * refusing one bound to any other.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    #[\Override]
    public function record(Proof $proof): void
    {
        $owner       = ProofOwner::boundBy($proof->binding);
        $application = $proof->binding->application;
        $record      = $this->read($owner, $application);

        if ($record === null || $record['session'] !== $proof->binding->sessionId) {
            throw new ProofRefusedException('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.');
        }

        $record['proofs'][] = $proof->toArray();

        $this->write($owner, $application, ['session' => $record['session'], 'proofs' => self::bounded($record['proofs'])]);
    }

    /**
     * The proofs of the identity's current sign-in on the application that
     * still count, oldest first.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        $record = $this->read(ProofOwner::of($identity), $application);

        if ($record === null) {
            return [];
        }

        $restored = array_filter(array_map(self::restore(...), $record['proofs']));

        return CountingProofs::of($identity, $application, $record['session'], $restored);
    }

    /**
     * Stop counting every proof the identity made with the factor on this
     * session, on every application it has signed in to. Other sessions stop
     * counting it when the identity's verification generation is advanced.
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
     * Forget the identity's current sign-in on the application and every proof
     * of it, leaving its sign-ins on other applications alone.
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
     * The session id a sign-in is named by, refusing a blank one.
     *
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
     * Read a stored proof back, or `null` when it cannot be.
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
     * Keep at most `LIMIT` proofs, forgetting the earliest recorded other than
     * the latest first factor, so the sign-in's first factor is kept and an
     * additional proof is never crowded out by earlier first factors.
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
     * The owner's record on the application: its sign-in's session id and its
     * stored proofs, or `null` when it has none or what is stored is not one.
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
     * Store the owner's record on the application.
     *
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
     * The owner's records, keyed by application.
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
     * Every identity's records in the session, keyed by owner.
     *
     * @return array<array-key, mixed>
     */
    private function records(): array
    {
        $records = $this->session->get(self::SESSION_KEY);

        return is_array($records) ? $records : [];
    }
}
