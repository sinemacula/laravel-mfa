<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Contracts;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Verified sign-in recorder contract.
 *
 * How `Concerns\InteractsWithMfa::actingAsVerified()` begins a sign-in and puts
 * its proofs in it. The default begins the sign-in and records the proofs
 * through the bound `ProofStore`. Bind another when the store refuses proofs it
 * did not make itself, such as one backed by an authentication layer's
 * sessions, to begin the sign-in and record the evidence through that layer.
 *
 * The helper still reads the proofs back through the bound store, so whatever
 * is recorded must count there: a store that counts a proof only while the
 * identity holds the factor it names needs that factor arranged too, or the
 * same evidence recorded against one the identity holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface VerifiedSignInRecorder
{
    /**
     * Begin a new sign-in for the identity on the application, replacing any
     * earlier one there, and return its session id: the one the bound proof
     * store now names as the identity's current sign-in there.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     *
     * @throws \LogicException
     */
    public function begin(MultiFactorAuthenticatable $identity, string $application): string;

    /**
     * Record the identity's proof on the sign-in it is bound to, keeping the
     * time it was made at, its method, the kind of its channel and the
     * properties it observed, or throw.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void;
}
