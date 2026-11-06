<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * The event context without an authentication layer: the identity, the
 * application a bound `ApplicationResolver` names for the request, and the
 * request's IP address and user agent. It knows no principal, tenant or
 * session, which stay `null`: the Laravel session's id is a bearer secret and
 * never leaves it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DefaultEventContextResolver implements EventContextResolver
{
    /**
     * The context of an event about the identity: its type and id, and the
     * client's IP address and user agent when they are known.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(?MultiFactorAuthenticatable $identity, ?ClientContext $client): array
    {
        return EventContext::allowlist([
            'identity_type' => $identity === null ? null : IdentityType::of($identity),
            'identity_id'   => EventContext::scalarKey($identity?->getAuthIdentifier()),
            'ip'            => $client?->ip,
            'user_agent'    => $client?->userAgent,
        ]);
    }
}
