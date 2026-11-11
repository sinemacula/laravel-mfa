<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * What an event is about, as `EventContextResolver` is handed it. Any part may
 * be unknown: an operator's action names no sign-in.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EventSubject
{
    /** @var ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable The identity, when there is one. */
    public ?MultiFactorAuthenticatable $identity;

    /** @var ?string The application the operation ran through, if any. */
    public ?string $application;

    /** @var ?string The package's session id, which an authentication layer maps to its own session. */
    public ?string $signInId;

    /** @var \SineMacula\Laravel\Mfa\Context\ClientContext Unknown outside a request. */
    public ClientContext $client;

    /**
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
