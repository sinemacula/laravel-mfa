<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Keeps a session's proofs per identity, application and sign-in, failing
 * closed: a future, foreign or older-generation proof is never returned.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProofStore
{
    /**
     * Begin a sign-in named by the session id its proofs bind to, forgetting
     * the previous sign-in's proofs on that application.
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
     * The session id a proof must be bound to, or `null` when the store knows
     * no sign-in; ask once and pass it to `proofs()`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string;

    /**
     * Throw for a proof not bound to the identity's current sign-in, so a
     * surrounding transaction rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void;

    /**
     * Proofs that still count, oldest first in recorded order, and none unless
     * the session is still the current sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array;

    /**
     * Called once the factor is deleted. Stop counting every proof made with
     * it, on any session the store can reach, unless the bound
     * `SessionRevoker`, which the package tells next, voids them.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void;

    /**
     * Forget the sign-in and its proofs on the application, as on sign-out; a
     * no-op is allowed only when another layer has already ended it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function forget(MultiFactorAuthenticatable $identity, string $application): void;
}
