<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Resolves who a helper serves before it returns summaries, sends a code or
 * reveals a secret: the one place a pending session's allowed actions are
 * checked.
 *
 * The bound `PendingSessionResolver` is asked first. When the request carries a
 * pending session, it is served only when the helper names an action the
 * pending credential allows; otherwise nothing is served, and the guard's user
 * is never used in its place. A helper that names no action serves active
 * sessions only. A credential the resolver cannot validate is reported by the
 * resolver throwing, which is not caught. Without a pending session, the
 * identity the guard signed in is served. Either way, only a person is: the
 * bound `SubjectTypeResolver` decides.
 *
 * Stateless: the request and the seams are resolved on every call.
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

        /** The container the request and the seams are resolved from. */
        private Container $container,
    ) {}

    /**
     * The caller a helper that needs the given pending action serves, or
     * `null` when it serves nobody: a pending session that does not allow the
     * action (or any pending session, when no action is named), no signed-in
     * identity, or one that is not a person.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return ?\SineMacula\Laravel\Mfa\Context\Caller
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function resolve(?PendingAction $action): ?Caller
    {
        $pending = $this->pending();

        if ($pending !== null) {
            return $action !== null && $pending->allows($action) && $this->isPerson($pending->identity)
                ? new Caller($pending->identity, $pending)
                : null;
        }

        $identity = CurrentIdentity::resolve();

        return $identity !== null && $this->isPerson($identity) ? new Caller($identity) : null;
    }

    /**
     * The application the caller is served on: the pending session's, or the
     * current request's (see `Proofs\ProofService::application()`).
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function application(Caller $caller): string
    {
        return $caller->pending?->application ?? $this->container->make(ProofService::class)->application();
    }

    /**
     * What a challenge or ceremony the caller takes part in is bound to: the
     * caller, its application, its session and the purpose. The session is
     * the pending session's, or the identity's current sign-in on the
     * application the proof store knows of; `null` without one, so nothing is
     * bound to a session no proof could be recorded on.
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
        $application = $this->application($caller);
        $session     = $caller->pending?->sessionId ?? $this->container->make(ProofStore::class)->currentSession($caller->identity, $application);

        if ($session === null) {
            return null;
        }

        $owner = ProofOwner::of($caller->identity);

        return new ProofBinding($owner->type, $owner->key, $application, $session, $purpose);
    }

    /**
     * The request's pending session, as the bound resolver reads it, or `null`
     * without a request or a pending session.
     *
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function pending(): ?PendingContext
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        return $request instanceof Request
            ? $this->container->make(PendingSessionResolver::class)->resolve($request)
            : null;
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
