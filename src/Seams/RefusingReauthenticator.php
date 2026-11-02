<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;

/**
 * The default `Reauthenticator`: without an authentication layer, or an
 * application's own binding, nothing can prove the first factor again, so no
 * reauthentication is ever made. Enrolling a first additional factor on an
 * active session, which needs one, fails closed until the application binds
 * its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingReauthenticator implements Reauthenticator
{
    /**
     * No proof, whoever asks.
     *
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
