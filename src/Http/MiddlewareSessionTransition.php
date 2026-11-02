<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * The default `SessionTransition`: without an authentication layer there is no
 * session state to change, because the `mfa` middleware
 * (`Middleware\EnsureMfaRequirementIsMet`) is the gate. It works the whole
 * requirement out again on every request and judges the session's proofs
 * against it, so a session left short is refused on every route that carries
 * `mfa` until it meets it again, and nothing handed to this call needs keeping.
 * The session keeps its proofs, as a pending session does, and is asked for
 * what it lacks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MiddlewareSessionTransition implements SessionTransition
{
    /**
     * Leave access to the `mfa` middleware, which gates it until the
     * requirement is met.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @return void
     */
    #[\Override]
    public function returnToPending(MultiFactorAuthenticatable $identity, string $application, Requirement $outstanding): void
    {
        // Nothing to change: the middleware judges the requirement afresh on
        // the next request.
    }
}
