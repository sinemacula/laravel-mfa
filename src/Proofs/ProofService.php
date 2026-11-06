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
 * Reads a caller's proofs through the bound `ProofStore`, on the caller's
 * application, and begins and ends an identity's sign-in on the application
 * named. No request is read. Proofs are recorded by the seams a verification
 * hands its result to (see `ProofStoreCompletion`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the store and the seams are read from. */
        private Container $container,
    ) {}

    /**
     * The proofs of the signed-in person's sign-in on the current application
     * that still count, oldest first: none without an MFA-capable person or a
     * sign-in, and none on a pending session, whose proofs are the
     * authentication layer's (see `Context\CallerContextResolver`).
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

        return $this->store()->proofs($identity, $caller->application);
    }

    /**
     * Begin a new sign-in for the identity on the application, as the guard
     * signed it in to, named by a fresh random id, so nothing the identity
     * proved before there carries over.
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
     * Forget the identity's sign-in on the application, as the guard signed it
     * out of, and every proof of it.
     *
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
     * Stop counting every proof the identity made with the factor.
     *
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
     * Resolve the bound proof store.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): ProofStore
    {
        return $this->container->make(ProofStore::class);
    }
}
