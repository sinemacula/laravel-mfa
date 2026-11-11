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
 * The first factor a session started with, read only from a trusted source so
 * the combination policy can decide which factor may follow it. An unknown
 * first factor accepts no factor after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionFirstFactor
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The store and resolver are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * A caller holding a pending session is never answered from an active
     * sign-in, so its credential reaches no other session.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function forBinding(MultiFactorAuthenticatable $identity, ProofBinding $binding, ?PendingContext $pending): ?Proof
    {
        $owner = ProofOwner::of($identity);

        if (!$owner->owns($binding)) {
            return null;
        }

        if ($pending !== null) {
            return $pending->sessionId === $binding->sessionId && $pending->application === $binding->application
                ? $this->ofPending($identity, $pending)
                : null;
        }

        $session = $this->container->make(ProofStore::class)->currentSession($identity, $binding->application);

        return $session !== null && $session === $binding->sessionId ? $this->firstFactorOf($identity, $binding->application, $session) : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function ofPending(MultiFactorAuthenticatable $identity, PendingContext $pending): ?Proof
    {
        return self::isTrusted($pending->firstFactor, $identity, $pending->application, $pending->sessionId) ? $pending->firstFactor : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function current(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $session = $this->container->make(ProofStore::class)->currentSession($identity, $application);

        return $session === null ? null : $this->firstFactorOf($identity, $application, $session);
    }

    /**
     * Oldest first, led by a trusted resolver's first factor when the store
     * holds none.
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
        $session = $this->container->make(ProofStore::class)->currentSession($identity, $application);

        return $session === null ? [] : $this->proofsOf($identity, $application, $session);
    }

    /**
     * Pinned to the named sign-in, so one replaced between two reads lends its
     * successor's proofs to neither.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function proofsOf(MultiFactorAuthenticatable $identity, string $application, string $session): array
    {
        $proofs = $this->container->make(ProofStore::class)->proofs($identity, $application, $session);

        foreach ($proofs as $proof) {
            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                return $proofs;
            }
        }

        $firstFactor = $this->resolved($identity, $application, $session);

        return $firstFactor === null ? $proofs : [$firstFactor, ...$proofs];
    }

    /**
     * The latest recorded first factor, else the bound resolver's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function firstFactorOf(MultiFactorAuthenticatable $identity, string $application, string $session): ?Proof
    {
        $recorded = null;

        foreach ($this->container->make(ProofStore::class)->proofs($identity, $application, $session) as $proof) {
            $recorded = $proof->kind === ProofKind::FIRST_FACTOR ? $proof : $recorded;
        }

        return $recorded ?? $this->resolved($identity, $application, $session);
    }

    /**
     * Only while the named session is still current, so a resolver answering
     * for a replaced sign-in lends it nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function resolved(MultiFactorAuthenticatable $identity, string $application, string $session): ?Proof
    {
        if ($this->container->make(ProofStore::class)->currentSession($identity, $application) !== $session) {
            return null;
        }

        $resolved = $this->container->make(FirstFactorResolver::class)->resolve($identity, $application);

        return $resolved !== null && self::isTrusted($resolved, $identity, $application, $session) ? $resolved : null;
    }

    /**
     * Bound to the sign-in, of the current verification generation and not
     * dated after now.
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
