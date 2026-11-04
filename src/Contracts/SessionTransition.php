<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * Session transition contract.
 *
 * Judges the identity's current session again after a change to its factors
 * made on an active session: a factor confirmed, a passkey registered as a
 * factor, or a factor removed when the bound `SessionRevoker` did not judge the
 * session itself. A layer with sessions of its own keeps the session active,
 * returns it to pending, so its access stops at once and it can take only the
 * pending actions until the outstanding requirement is met, or ends it, by its
 * own rules. Without an authentication layer there is no pending session to
 * return to, and the default (`Http\MiddlewareSessionTransition`) leaves the
 * `mfa` middleware to gate access until the requirement is met.
 *
 * Called after every such change, whether or not the package finds the session
 * short, inside the identity's transaction once the package's locks are held
 * and its rows have changed; a layer that locks a session row of its own locks
 * it last.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionTransition
{
    /**
     * Judge the session the change was made on again, and return what the
     * caller is to receive, such as a pending session's new credential, or
     * `null` with nothing to return.
     *
     * Returning means the change was handled, which is not to say a session
     * remains: one the layer ended, or found ended already, returns too. A
     * session that cannot be handled is reported by throwing, never by
     * returning, so the change the call is part of rolls back. What is returned
     * reaches the caller in the change's result, and must not leave before the
     * change commits.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return ?object
     *
     * @throws \RuntimeException
     */
    public function factorChanged(SessionChange $change): ?object;
}
