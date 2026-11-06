<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * Session revoker contract.
 *
 * Ends the identity's sessions as part of a change to its factors,
 * synchronously and inside the change, on the storage connection after the
 * package's locks: removing a factor ends the identity's other sessions, and a
 * reset ends all of them. It is mandatory, whatever revocation settings the
 * authentication layer has for other events; an event reports the change but
 * never stands in for this call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionRevoker
{
    /**
     * The factor was removed from the session's sign-in: end every session of
     * the identity except that one, and say whether it judged that one again
     * itself.
     *
     * The session is the sign-in the removal was made from (the session id the
     * package's proofs are bound to), never one resolved from elsewhere; an
     * implementation that cannot match it to the identity's own session throws.
     * When the factor's removal leaves that session short, an implementation
     * may judge it again by its own rules (returning it to pending, or ending
     * it) and say so with `RemovalRevocation::judged()`, carrying what the
     * caller is to receive; the package then hands no shortfall to the bound
     * `SessionTransition`. With `RemovalRevocation::othersEnded()` the package
     * judges the session itself, as without an authentication layer.
     *
     * Returning means the sessions are ended. A session that cannot be ended is
     * reported by throwing, never by returning, so the change the call is part
     * of rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \RuntimeException
     */
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $application, string $session): RemovalRevocation;

    /**
     * End every session of the identity, the current one included.
     *
     * Returning means the sessions are ended. A session that cannot be ended is
     * reported by throwing, never by returning, so the change the call is part
     * of rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \RuntimeException
     */
    public function revokeAll(MultiFactorAuthenticatable $identity): void;
}
