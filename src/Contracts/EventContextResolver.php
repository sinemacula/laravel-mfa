<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Context\ClientContext;

/**
 * Event context resolver contract.
 *
 * The context every event carries, as an allowlist of scalar values: the
 * identity, its principal, the active tenant, the session and the client (IP
 * and user agent), by id and type, never a model, a secret or a full
 * destination, so a queued listener can serialise it safely. A value it does
 * not know is `null`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EventContextResolver
{
    /**
     * The context of an event about the identity, for the client the action was
     * served to when it is known. The application is the package's own:
     * whatever this answers for it is replaced by the application the event is
     * about.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return array<string, int|string|null>
     */
    public function resolve(?MultiFactorAuthenticatable $identity, ?ClientContext $client): array;
}
