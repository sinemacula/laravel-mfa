<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * Event context without an authentication layer: identity and client only. The
 * session stays `null` because the Laravel session id is a bearer secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DefaultEventContextResolver implements EventContextResolver
{
    /**
     * The sign-in id is this package's own, so it is not given as the session.
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
