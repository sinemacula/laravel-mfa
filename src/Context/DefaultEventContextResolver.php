<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

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
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the application resolver is read from. */
        private Container $container,
    ) {}

    /**
     * The context of an event about the identity, from the request when there
     * is one.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\Illuminate\Http\Request  $request
     * @return array<string, int|string|null>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function resolve(?MultiFactorAuthenticatable $identity, ?Request $request): array
    {
        return EventContext::allowlist([
            'identity_type' => $identity === null ? null : CurrentIdentity::typeOf($identity),
            'identity_id'   => EventContext::scalarKey($identity?->getAuthIdentifier()),
            'application'   => $this->application($request),
            'ip'            => $request?->ip(),
            'user_agent'    => $request?->userAgent(),
        ]);
    }

    /**
     * The application a bound `ApplicationResolver` names for the request, or
     * `null` without either.
     *
     * @param  ?\Illuminate\Http\Request  $request
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function application(?Request $request): ?string
    {
        if ($request === null || !$this->container->bound(ApplicationResolver::class)) {
            return null;
        }

        return $this->container->make(ApplicationResolver::class)->resolve($request);
    }
}
