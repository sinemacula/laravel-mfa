<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;

/**
 * The default proof store: each identity's current sign-in and the full records
 * of its proofs, kept in the Laravel session under `mfa.proofs`.
 *
 * A sign-in begins on Laravel's `Login` event, or through
 * `GuardHooks::signedIn()` for a guard that fires none, and ends on `Logout` or
 * `GuardHooks::signedOut()`; beginning one forgets the proofs of the one
 * before. Records are kept per identity, by its type and key, so two identity
 * types sharing a key never share one, and every proof is read back against the
 * identity, the application, the sign-in and the identity's verification
 * generation it is asked for.
 *
 * It fails closed. A proof bound to another sign-in is refused when it is
 * recorded. When the proofs are read, one is left out when it is bound to
 * another identity, application or sign-in, was made after now, was made under
 * another verification generation than the identity's current one, or cannot be
 * read back; an identity with no sign-in has none.
 *
 * The records are bounded: an identity's sign-in keeps at most 50 proofs, and
 * recording more forgets the earliest recorded, though never the first factor.
 * The session holds each channel's full destination, so it must be stored where
 * the application keeps its other session secrets.
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
     * Begin a new sign-in for the identity, forgetting every proof of the one
     * before.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $sessionId): void
    {
        $this->write(ProofOwner::of($identity), ['session' => self::sessionId($sessionId), 'proofs' => []]);
    }

    /**
     * The session id of the identity's current sign-in, or `null` when it has
     * none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity): ?string
    {
        return $this->read(ProofOwner::of($identity))['session'] ?? null;
    }

    /**
     * Record a proof for its identity's current sign-in, refusing one bound to
     * any other.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    #[\Override]
    public function record(Proof $proof): void
    {
        $owner  = ProofOwner::boundBy($proof->binding);
        $record = $this->read($owner);

        if ($record === null || $record['session'] !== $proof->binding->sessionId) {
            throw new ProofRefusedException('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.');
        }

        $record['proofs'][] = $proof->toArray();

        $this->write($owner, ['session' => $record['session'], 'proofs' => self::bounded($record['proofs'])]);
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
        $owner  = ProofOwner::of($identity);
        $record = $this->read($owner);

        if ($record === null) {
            return [];
        }

        $generation = VerificationGeneration::current($identity);
        $now        = CarbonImmutable::now();
        $proofs     = [];

        foreach ($record['proofs'] as $stored) {

            $proof = self::restore($stored);

            if ($proof === null) {
                continue;
            }

            $counts = $owner->owns($proof->binding)
                && $proof->binding->application === $application
                && $proof->binding->sessionId   === $record['session']
                && $proof->generation           === $generation
                && $proof->provedAt->lessThanOrEqualTo($now);

            if (!$counts) {
                continue;
            }

            $proofs[] = $proof;
        }

        usort($proofs, static fn (Proof $a, Proof $b): int => $a->provedAt <=> $b->provedAt);

        return $proofs;
    }

    /**
     * Stop counting every proof the identity made with the factor on this
     * session. Other sessions stop counting it when the identity's verification
     * generation is advanced.
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
        $owner  = ProofOwner::of($identity);
        $record = $this->read($owner);

        if ($record === null) {
            return;
        }

        $kept = array_filter($record['proofs'], static fn (array $stored): bool => ($stored['reference'] ?? null) !== $factorId);

        $this->write($owner, ['session' => $record['session'], 'proofs' => array_values($kept)]);
    }

    /**
     * Forget the identity's current sign-in and every proof of it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity): void
    {
        $slot    = ProofOwner::of($identity)->slot();
        $records = $this->records();

        unset($records[$slot]);

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
     * Keep at most `LIMIT` proofs, forgetting the earliest recorded that is not
     * a first factor.
     *
     * @param  list<array<array-key, mixed>>  $proofs
     * @return list<array<array-key, mixed>>
     */
    private static function bounded(array $proofs): array
    {
        while (count($proofs) > self::LIMIT) {

            $index = null;

            foreach ($proofs as $position => $stored) {
                if (($stored['kind'] ?? null) !== ProofKind::FIRST_FACTOR->value) {
                    $index = $position;
                    break;
                }
            }

            if ($index === null) {
                break;
            }

            unset($proofs[$index]);

            $proofs = array_values($proofs);
        }

        return $proofs;
    }

    /**
     * The owner's record: its sign-in's session id and its stored proofs, or
     * `null` when it has none or what is stored is not one.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return ?array{session: string, proofs: list<array<array-key, mixed>>}
     */
    private function read(ProofOwner $owner): ?array
    {
        $record = $this->records()[$owner->slot()] ?? null;

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
     * Store the owner's record.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  array{session: string, proofs: list<array<array-key, mixed>>}  $record
     * @return void
     */
    private function write(ProofOwner $owner, array $record): void
    {
        $records = $this->records();

        $records[$owner->slot()] = $record;

        $this->session->put(self::SESSION_KEY, $records);
    }

    /**
     * Every identity's record in the session, keyed by owner.
     *
     * @return array<array-key, mixed>
     */
    private function records(): array
    {
        $records = $this->session->get(self::SESSION_KEY);

        return is_array($records) ? $records : [];
    }
}
