<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Challenge gateway contract.
 *
 * Sends and checks the codes of a delivered factor (SMS or email) as challenges
 * bound to the identity, the application, the session, the factor and the
 * purpose, stored as a keyed hash and consumed atomically by whoever owns them.
 * This package supplies only a confirmed factor of the identity, of an enabled
 * type, that the combination policy accepts, and counts the outcome against the
 * factor and the identity.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ChallengeGateway
{
    /**
     * Send a code for the factor, bound as the binding says, and return the
     * challenge's id.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return string
     */
    public function send(Factor $factor, ProofBinding $binding): string;

    /**
     * Whether the code answers the challenge, consuming it when it does. A code
     * matches only the challenge, factor, session and purpose it was issued
     * for.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): bool;
}
