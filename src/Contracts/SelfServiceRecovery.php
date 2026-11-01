<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Self-service recovery contract.
 *
 * An application's own recovery for a person who has lost every factor and
 * their recovery codes, for example a delayed reset with notice to the person.
 * Recovery never goes through the sign-in flow: a reset by someone else is the
 * package's own helper, and this contract is what an application adds beside
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SelfServiceRecovery
{
    /**
     * Whether the application offers the identity self-service recovery.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return bool
     */
    public function isOffered(MultiFactorAuthenticatable $identity, string $application): bool;

    /**
     * Start the identity's self-service recovery on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public function start(MultiFactorAuthenticatable $identity, string $application): void;
}
