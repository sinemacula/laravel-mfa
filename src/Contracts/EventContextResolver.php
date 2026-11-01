<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;

/**
 * Event context resolver contract.
 *
 * The context every event carries, as an allowlist of scalar values: the
 * identity, its principal, the active tenant, the application, the session and
 * the request (IP and user agent), by id and type, never a model, a secret or a
 * full destination, so a queued listener can serialise it safely. A value it
 * does not know is `null`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EventContextResolver
{
    /**
     * The context of an event about the identity, from the request when there
     * is one.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\Illuminate\Http\Request  $request
     * @return array<string, int|string|null>
     */
    public function resolve(?MultiFactorAuthenticatable $identity, ?Request $request): array;
}
