<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Records and reads the current identity's proofs through the bound
 * `ProofStore`, on the application of the current request: the one a bound
 * `ApplicationResolver` names, or the default guard's name without one.
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

        /** The container the store, the request and the application resolver are read from. */
        private Container $container,
    ) {}

    /**
     * The proofs of the current identity's sign-in on the current application
     * that still count, oldest first: none without an MFA-capable identity or a
     * sign-in.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function proofs(): array
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return [];
        }

        return $this->store()->proofs($identity, $this->application());
    }

    /**
     * Whether the identity has a sign-in the store knows of, so a proof it
     * makes now can be recorded.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function hasSignIn(MultiFactorAuthenticatable $identity): bool
    {
        return $this->store()->currentSession($identity) !== null;
    }

    /**
     * Record a proof the identity has just made on the current application,
     * bound to its current sign-in and verification generation, observing
     * nothing beyond the proof itself, and return it; `null` when the identity
     * has no sign-in the store knows of, so nothing is recorded.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  ?string  $reference
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function record(MultiFactorAuthenticatable $identity, ProofKind $kind, string $method, ?Channel $channel, ?string $reference, Purpose $purpose): ?Proof
    {
        $store   = $this->store();
        $session = $store->currentSession($identity);

        if ($session === null) {
            return null;
        }

        $owner = ProofOwner::of($identity);

        $proof = new Proof(
            $kind,
            $method,
            $channel,
            $reference,
            ObservedProperties::none(),
            CarbonImmutable::now(),
            new ProofBinding($owner->type, $owner->key, $this->application(), $session, $purpose),
            VerificationGeneration::current($identity),
        );

        $store->record($proof);

        return $proof;
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
     * The application of the current request: the one a bound
     * `ApplicationResolver` names for it, or the default guard's name.
     *
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function application(): string
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        if ($request instanceof Request && $this->container->bound(ApplicationResolver::class)) {
            return $this->container->make(ApplicationResolver::class)->resolve($request);
        }

        return Auth::getDefaultDriver();
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
