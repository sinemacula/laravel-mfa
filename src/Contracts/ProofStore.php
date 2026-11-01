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
 * It fails closed: no record, a proof in the future, one made under an older
 * verification generation, or one of another identity or application is not
 * returned, and a proof made with a factor that was later removed stops
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
     * Record a proof for the session it is bound to.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    public function record(Proof $proof): void;

    /**
     * The proofs of the identity's current session on the application that
     * still count, oldest first.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array;

    /**
     * Stop counting every proof the identity made with the factor, on the
     * current session as on any other the store can reach.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void;

    /**
     * Forget every proof of the identity's current session, as on sign-in and
     * sign-out, so another identity on a reused session inherits nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public function forget(MultiFactorAuthenticatable $identity): void;
}
