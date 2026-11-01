<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Session transition contract.
 *
 * Returns the identity's current session to pending when a change inside a
 * request (a switch, a refresh, a factor change) leaves it short of a
 * requirement: its access stops at once, and until the outstanding requirement
 * is met the session can take only the pending actions.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionTransition
{
    /**
     * Return the identity's current session on the application to pending,
     * owing the requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @return void
     */
    public function returnToPending(MultiFactorAuthenticatable $identity, string $application, Requirement $outstanding): void;
}
