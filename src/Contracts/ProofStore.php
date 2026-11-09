<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Proof store contract.
 *
 * Keeps the proofs a session has made, keyed by the identity, the application
 * and the sign-in instance, with the identity's verification generation, so
 * freshness, levels and requirements are evaluated against the session's
 * records rather than one time and a list of `amr` values.
 *
 * A sign-in instance is named by the session id every proof made in it is bound
 * to: it begins when the identity signs in to an application, and a proof bound
 * to any other session is never kept. An identity's sign-ins on different
 * applications are separate: beginning or forgetting one leaves the others
 * alone. The default keeps the records in the Laravel session;
 * a stateless guard rebinds the contract, keyed by an id that names one
 * sign-in, not merely a device.
 *
 * It fails closed: no record, a proof in the future, one made under an older
 * verification generation, or one of another identity, application or sign-in
 * is not returned, and a proof made with a factor that was later removed stops
 * counting once it is forgotten.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProofStore
{
    /**
     * Begin a new sign-in for the identity on the application, named by the
     * session id its proofs will be bound to, forgetting every proof of the
     * sign-in before it on that application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void;

    /**
     * The session id of the identity's current sign-in on the application, the
     * one a proof must be bound to for the store to keep it, or `null` when the
     * identity has no sign-in there the store knows of.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string;

    /**
     * Record a proof for the sign-in it is bound to.
     *
     * A proof that is not bound to its identity's current sign-in on its
     * application is refused by throwing, never kept, so a caller recording it
     * inside a transaction rolls that change back with it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    public function record(Proof $proof): void;

    /**
     * The proofs of the identity's current sign-in on the application that
     * still count, oldest first, with proofs made at the same instant in the
     * order they were recorded.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array;

    /**
     * Stop counting every proof the identity made with the factor, on the
     * current session as on any other the store can reach.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void;

    /**
     * Forget the identity's current sign-in on the application and every proof
     * of it, as on sign-out, so another identity on a reused session inherits
     * nothing, leaving its sign-ins on other applications alone.
     *
     * A store backed by another layer's sign-ins may do nothing here only when
     * that layer has already ended, or unbound, the sign-in before this is
     * called, on every path that calls it (the sign-out listener and
     * `Proofs\GuardHooks::signedOut()` alike): `currentSession()` then answers
     * `null` and `proofs()` nothing for it, and the identity's sign-ins on
     * other applications are left alone.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function forget(MultiFactorAuthenticatable $identity, string $application): void;
}
