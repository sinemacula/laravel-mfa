<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
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
 * The gateway asks `Attempts\ChallengeCounters::isUsable()` before it sends or
 * checks a code, and reports every outcome through `report()` in the same
 * transaction that consumes the challenge, never later: a deferred report would
 * let parallel guesses overrun the per-identity cap. A delivery is never
 * reported, and `CodeSent` and the verification events are not the gateway's to
 * dispatch: `Verification\VerificationService` reports whichever gateway is
 * bound. Without an authentication layer, the package's own codes
 * (`Codes\PackageChallengeGateway`) are bound.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ChallengeGateway
{
    /**
     * Send a code for the factor, bound as the binding says: the challenge's id
     * and when the code stops working, or why none was sent and, when waiting
     * will help, how long to wait.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     */
    public function send(Factor $factor, ProofBinding $binding): SendResult;

    /**
     * Whether the code answers the challenge, consuming it when it does. A code
     * matches only the challenge, factor, session and purpose it was issued
     * for. A challenge that is absent, or another binding's, fails as
     * `not_found`, whatever the code; a used challenge fails as `replayed` for
     * the code that used it and `expired` for any other. Every outcome of a
     * code that was checked has been reported; one refused before that has not.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     */
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome;
}
