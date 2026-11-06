<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * The event context without an authentication layer: the identity, and the IP
 * address and user agent of the client the action was served to (the event adds
 * the application it ran through). It knows no principal, tenant or session,
 * which stay `null`: the Laravel session's id is a bearer secret and never
 * leaves it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DefaultEventContextResolver implements EventContextResolver
{
    /**
     * The context of an event about the subject: its identity's type and id,
     * and the client's IP address and user agent when they are known. The
     * sign-in is this package's own id, not a session of any authentication
     * layer, so it is not given as the session.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        $identity = $subject->identity;

        return EventContext::allowlist([
            'identity_type' => $identity === null ? null : IdentityType::of($identity),
            'identity_id'   => EventContext::scalarKey($identity?->getAuthIdentifier()),
            'ip'            => $subject->client->ip,
            'user_agent'    => $subject->client->userAgent,
        ]);
    }
}
