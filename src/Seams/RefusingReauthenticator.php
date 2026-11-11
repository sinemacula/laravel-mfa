<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;

/**
 * Default `Reauthenticator`: nothing can prove the first factor again, so a
 * first enrolment on an active session fails closed until the application binds
 * one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingReauthenticator implements Reauthenticator
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return null
     */
    #[\Override]
    public function reauthenticate(MultiFactorAuthenticatable $identity, string $application): null
    {
        return null;
    }
}
