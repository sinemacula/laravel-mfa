<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;

/**
 * Reads a caller's proofs through the bound `ProofStore`, and begins and ends
 * sign-ins; proofs are recorded by the completion seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofService
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * None without a person or a sign-in, and none on a pending session, whose
     * proofs are the authentication layer's.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function proofs(CallerContext $caller): array
    {
        $identity = $this->container->make(CallerContextResolver::class)->resolve($caller, null)?->identity;

        if ($identity === null) {
            return [];
        }

        $store   = $this->store();
        $session = $store->currentSession($identity, $caller->application);

        return $session === null ? [] : $store->proofs($identity, $caller->application, $session);
    }

    /**
     * Named by a fresh random id, so nothing proved there before carries over.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function beginSignIn(MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->store()->begin($identity, $application, Str::lower((string) Str::ulid()));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function endSignIn(MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->store()->forget($identity, $application);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        $this->store()->forgetFactor($identity, $factorId);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): ProofStore
    {
        return $this->container->make(ProofStore::class);
    }
}
