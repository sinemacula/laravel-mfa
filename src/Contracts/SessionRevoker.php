<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Session revoker contract.
 *
 * Ends the identity's sessions as part of a change to its factors,
 * synchronously and inside the change: removing a factor ends the identity's
 * other sessions, and a reset ends all of them. It is mandatory, whatever
 * revocation settings the authentication layer has for other events; an event
 * reports the change but never stands in for this call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionRevoker
{
    /**
     * End every session of the identity except the current one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public function revokeOthers(MultiFactorAuthenticatable $identity): void;

    /**
     * End every session of the identity, the current one included.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public function revokeAll(MultiFactorAuthenticatable $identity): void;
}
