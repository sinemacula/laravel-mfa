<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * The first factor a session started with, read only from a trusted source, so
 * the combination policy can decide which factor may follow it.
 *
 * For a pending session it is the pending context's own first factor. For an
 * active one it is the latest first factor the proof store holds for the
 * identity's current sign-in, or, when it holds none, the bound
 * `FirstFactorResolver`'s answer, which counts only when it is a first factor
 * of the identity on the application, bound to the current sign-in, made under
 * the identity's current verification generation and not after now. A session
 * whose first factor is not known has none, so no factor is accepted after it.
 *
 * Stateless: the request, the store and the resolver are resolved on every
 * call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionFirstFactor
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** The container the store and the resolver are resolved from. */
        private Container $container,

        /** The reader of the request's pending session. */
        private CallerContextResolver $callers,
    ) {}

    /**
     * The first factor of the session the binding names: the pending session's
     * when the request carries one and the binding names it, otherwise the
     * identity's current sign-in's when the binding names it; `null` for any
     * other session. A request carrying a pending session is never answered
     * from an active sign-in, so its credential reaches no other session.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function forBinding(MultiFactorAuthenticatable $identity, ProofBinding $binding): ?Proof
    {
        $owner   = ProofOwner::of($identity);
        $pending = $this->callers->pending();

        if (!$owner->owns($binding)) {
            return null;
        }

        if ($pending !== null) {
            return $pending->sessionId === $binding->sessionId && $pending->application === $binding->application && $owner->owns($pending->firstFactor->binding)
                ? $pending->firstFactor
                : null;
        }

        $session = $this->container->make(ProofStore::class)->currentSession($identity, $binding->application);

        return $session !== null && $session === $binding->sessionId ? $this->current($identity, $binding->application) : null;
    }

    /**
     * The first factor of the identity's current sign-in on the application, or
     * `null` when it has no sign-in or its first factor is not known.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function current(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $store   = $this->container->make(ProofStore::class);
        $session = $store->currentSession($identity, $application);

        if ($session === null) {
            return null;
        }

        $recorded = null;

        foreach ($store->proofs($identity, $application) as $proof) {
            $recorded = $proof->kind === ProofKind::FIRST_FACTOR ? $proof : $recorded;
        }

        if ($recorded !== null) {
            return $recorded;
        }

        $resolved = $this->container->make(FirstFactorResolver::class)->resolve($identity, $application);

        return $resolved !== null && self::isTrusted($resolved, $identity, $application, $session) ? $resolved : null;
    }

    /**
     * The proofs of the identity's current sign-in on the application that
     * still count, oldest first, with its first factor ahead of them when the
     * store holds none and the bound resolver reports a trusted one; none
     * without a sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        $store = $this->container->make(ProofStore::class);

        if ($store->currentSession($identity, $application) === null) {
            return [];
        }

        $proofs = $store->proofs($identity, $application);

        foreach ($proofs as $proof) {
            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                return $proofs;
            }
        }

        $firstFactor = $this->current($identity, $application);

        return $firstFactor === null ? $proofs : [$firstFactor, ...$proofs];
    }

    /**
     * Whether a resolved first factor may count for the sign-in: a first factor
     * of the identity on the application, bound to the sign-in, made under the
     * identity's current verification generation and not after now.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isTrusted(Proof $firstFactor, MultiFactorAuthenticatable $identity, string $application, string $session): bool
    {
        return $firstFactor->kind === ProofKind::FIRST_FACTOR
            && ProofOwner::of($identity)->ownsSignIn($firstFactor->binding, $application, $session)
            && $firstFactor->generation === VerificationGeneration::current($identity)
            && $firstFactor->provedAt->lessThanOrEqualTo(CarbonImmutable::now());
    }
}
