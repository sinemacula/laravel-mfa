<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The one place a pending session's allowed actions are checked. A refused
 * pending session is never served as another identity, and only a person is
 * served.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerContextResolver
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * With no action named, only an active session is served.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  ?\SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function resolve(CallerContext $context, ?PendingAction $action): ?Caller
    {
        $pending = $context->pending;

        if ($pending !== null) {
            return $action !== null && $pending->allows($action) ? $this->pendingCaller($pending, $context->client) : null;
        }

        return $this->activeCaller($context);
    }

    /**
     * Whose factors a route parameter binds to, not whether the route may run;
     * each action checks its own.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forFactorBinding(CallerContext $context): ?Caller
    {
        $pending = $context->pending;

        if ($pending !== null) {
            return $this->allowsNamingAFactor($pending) ? $this->pendingCaller($pending, $context->client) : null;
        }

        return $this->activeCaller($context);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @return string
     */
    public function application(Caller $caller): string
    {
        return $caller->application;
    }

    /**
     * `null` without a pending session or current sign-in, so nothing is bound
     * to a session no proof could be recorded on.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return ?\SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function binding(Caller $caller, Purpose $purpose): ?ProofBinding
    {
        $session = $caller->pending->sessionId ?? $this->container->make(ProofStore::class)->currentSession($caller->identity, $caller->application);

        if ($session === null) {
            return null;
        }

        $owner = ProofOwner::of($caller->identity);

        return new ProofBinding($owner->type, $owner->key, $caller->application, $session, $purpose);
    }

    /**
     * The caller as it stands now under the identity's lock, or `null` when it
     * no longer matches the captured binding.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  ?\SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function still(Caller $caller, ?PendingAction $action, ProofBinding $binding): ?Caller
    {
        $now = $caller->pending === null
            ? $this->activeCaller(CallerContext::forIdentity($caller->identity, $caller->application, $caller->client))
            : $this->revalidated($caller->pending, $action, $caller->client);

        return $now !== null && $this->binding($now, $binding->purpose)?->toArray() === $binding->toArray() ? $now : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  ?\SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function revalidated(PendingContext $pending, ?PendingAction $action, ClientContext $client): ?Caller
    {
        $now = $this->container->make(PendingSessionResolver::class)->revalidate($pending);

        return $now !== null && $action !== null && $now->allows($action) ? $this->pendingCaller($now, $client) : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function pendingCaller(PendingContext $pending, ClientContext $client): ?Caller
    {
        return $this->isPerson($pending->identity) ? new Caller($pending->identity, $pending, $pending->application, $client) : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function activeCaller(CallerContext $context): ?Caller
    {
        $identity = $context->identity;

        return $identity !== null && $this->isPerson($identity) ? new Caller($identity, null, $context->application, $context->client) : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return bool
     */
    private function allowsNamingAFactor(PendingContext $pending): bool
    {
        return $pending->allows(PendingAction::LIST_FACTORS)
            || $pending->allows(PendingAction::SEND_CODE)
            || $pending->allows(PendingAction::VERIFY);
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isPerson(Authenticatable $identity): bool
    {
        return $this->container->make(SubjectTypeResolver::class)->isPerson($identity);
    }
}
