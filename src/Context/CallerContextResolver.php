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
 * Resolves who an action serves from its `CallerContext`: the one place a
 * pending session's allowed actions are checked. No request is read.
 *
 * A pending session is served only when the action names an action the pending
 * credential allows; otherwise nothing is served, and no other identity is used
 * in its place. An action that names no action serves active sessions only.
 * Either way, only a person is served: the bound `SubjectTypeResolver` decides.
 *
 * Under the identity's lock, `still()` checks the caller again: a pending
 * session through the bound `PendingSessionResolver`'s `revalidate()`, and an
 * active one through the proof store's current sign-in, with the binding the
 * action captured either way.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerContextResolver
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the seams are resolved from. */
        private Container $container,
    ) {}

    /**
     * The caller an action that needs the given pending action serves, or
     * `null` when it serves nobody: a pending session that does not allow the
     * action (or any pending session, when no action is named), nobody, or an
     * identity that is not a person.
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
     * The caller a bound factor route parameter is held to: a pending session
     * whose credential allows one of the actions that name an existing factor,
     * otherwise an identity on an active session. A pending session allowing
     * none of them is served nothing. It says whose factors bind, not that the
     * route may run: each action asks for its own.
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
     * The application the caller is served on.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @return string
     */
    public function application(Caller $caller): string
    {
        return $caller->application;
    }

    /**
     * What a challenge or ceremony the caller takes part in is bound to: the
     * caller, its application, its session and the purpose. The session is the
     * pending session's, or the identity's current sign-in on the application
     * the proof store knows of; `null` without one, so nothing is bound to a
     * session no proof could be recorded on.
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
     * The caller as it stands now, when it is still the one the binding was
     * captured for, or `null` when anything differs. A pending session is read
     * again through the bound resolver's `revalidate()`, and must still allow
     * the action and be a person's; the caller then served is the pending
     * session as it stands now. An active caller must still be a person, and
     * the proof store's current sign-in must still be the binding's.
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
     * The pending session read again, when it still stands and allows the
     * action.
     *
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
     * The pending session's identity, when it is a person.
     *
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
     * The context's identity on its active session, when it is a person.
     *
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
     * Whether the pending credential allows an action that names an existing
     * factor.
     *
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
     * Whether the bound resolver says the identity is a person.
     *
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
