<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;

/**
 * Dispatches events once the storage connection's transaction commits, never on
 * rollback. Events only report: nothing security-relevant needs a listener.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EventDispatcher
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolved per dispatch so the testing traits' transactions manager is used. */
        private Container $container,
    ) {}

    /**
     * Context from the bound resolver, cut to `EventContext::KEYS`. No request
     * is read.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @param  ?string  $signInId
     * @return array<string, int|string|null>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function context(?MultiFactorAuthenticatable $identity, ?string $application = null, ?ClientContext $client = null, ?string $signInId = null): array
    {
        $subject = new EventSubject($identity, $application, $signInId, $client);
        $context = EventContext::allowlist($this->container->make(EventContextResolver::class)->resolve($subject));

        $context['application'] = $application;

        return $context;
    }

    /**
     * Context from a stored row alone, for changes such as pruning, so the
     * current request's session or tenant is never attributed to it.
     *
     * @param  string  $type
     * @param  string  $key
     * @param  string  $application
     * @return array<string, int|string|null>
     */
    public function ownerContext(string $type, string $key, string $application): array
    {
        return EventContext::allowlist(['identity_type' => $type, 'identity_id' => $key, 'application' => $application]);
    }

    /**
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
