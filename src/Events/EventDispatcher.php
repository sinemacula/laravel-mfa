<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;

/**
 * The one way the package dispatches its events: once the change they report
 * has committed, so a listener never sees an event for a change that rolled
 * back, and each with the context the bound `EventContextResolver` gives.
 *
 * An event is dispatched at once when the storage connection has no open
 * transaction, otherwise when that transaction commits, and never when it rolls
 * back. A transaction open on another connection neither delays nor drops it,
 * since the package's changes are not made in it. The transactions manager is
 * read when an event is dispatched, as Laravel's dispatcher does, so the one
 * the testing traits swap in (which ignores their own wrapping transaction) is
 * the one consulted.
 *
 * Events report; they never enforce. Nothing security-relevant depends on a
 * listener running.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EventDispatcher
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the resolver, request, dispatcher and transactions are read from. */
        private Container $container,
    ) {}

    /**
     * The context of an event about the identity, from the bound resolver and
     * the request being served, cut down to `EventContext::KEYS`. The
     * application an operation ran through, when given, names the application.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?string  $application
     * @return array<string, int|string|null>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function context(?MultiFactorAuthenticatable $identity, ?string $application = null): array
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        $context = EventContext::allowlist($this->container->make(EventContextResolver::class)->resolve($identity, $request));

        $context['application'] = $application ?? $context['application'];

        return $context;
    }

    /**
     * Dispatch the event once the storage connection's open transaction, if
     * any, commits.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function dispatch(MfaEvent $event): void
    {
        $events = $this->container->make(Dispatcher::class);

        AfterStorageCommit::run($this->container, static fn () => $events->dispatch($event));
    }
}
