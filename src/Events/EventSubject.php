<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * What an event is about, as `EventContextResolver` is handed it: the identity,
 * the application the operation ran through, the sign-in the operation was
 * bound to, and the client it was served to. Each may be unknown: an operator's
 * action and an attempt's lockout name no sign-in, and nothing outside a
 * request knows the client.
 *
 * The sign-in is this package's own id for it, the session id a proof binding
 * and a pending session carry, which an authentication layer maps to its own
 * session, principal and tenant. It is given only where the operation captured
 * it, never looked up to decorate an event.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EventSubject
{
    /** @var ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable The identity the event is about, when there is one. */
    public ?MultiFactorAuthenticatable $identity;

    /** @var ?string The application the operation ran through, when it ran through one. */
    public ?string $application;

    /** @var ?string The sign-in the operation was bound to, when it captured one. */
    public ?string $signInId;

    /** @var \SineMacula\Laravel\Mfa\Context\ClientContext The client the operation was served to, or one of which nothing is known. */
    public ClientContext $client;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?string  $application
     * @param  ?string  $signInId
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     */
    public function __construct(?MultiFactorAuthenticatable $identity = null, ?string $application = null, ?string $signInId = null, ?ClientContext $client = null)
    {
        $this->identity    = $identity;
        $this->application = $application;
        $this->signInId    = $signInId;
        $this->client      = $client ?? ClientContext::unknown();
    }
}
