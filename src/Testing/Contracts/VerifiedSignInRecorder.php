<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * How `actingAsVerified()` begins a sign-in and records its proofs. Bind one
 * when the `ProofStore` refuses proofs it did not make, such as one backed by
 * an authentication layer's sessions.
 *
 * The helper records a password first factor, unless one is held, then one
 * additional factor proof for sign-in, both made at the time `begin()` is
 * given. It reads them back through the bound store, so they must count there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface VerifiedSignInRecorder
{
    /**
     * Begin a sign-in, replacing any earlier one, and return the session id the
     * bound store names as current, now or once the next proof completes it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     *
     * @throws \LogicException
     */
    public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string;

    /**
     * Record the proof on its bound sign-in, keeping its time, method, channel
     * kind and observed properties, or throw.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void;
}
