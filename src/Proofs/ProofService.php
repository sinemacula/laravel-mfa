<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Records and reads the current identity's proofs through the bound
 * `ProofStore`, on the application of the current request: the one a bound
 * `ApplicationResolver` names, or the default guard's name without one. It also
 * begins and ends an identity's sign-in on the application a guard signs it in
 * to.
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
     * The proofs of the signed-in person's sign-in on the current application
     * that still count, oldest first: none without an MFA-capable person or a
     * sign-in, and none on a pending session, whose proofs are the
     * authentication layer's (see `Context\CallerContextResolver`).
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function proofs(): array
    {
        $identity = $this->container->make(CallerContextResolver::class)->resolve(null)?->identity;

        if ($identity === null) {
            return [];
        }

        return $this->store()->proofs($identity, $this->application());
    }

    /**
     * Begin a new sign-in for the identity on the application the guard signed
     * it in to, named by a fresh random id, so nothing the identity proved
     * before there carries over.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function beginSignIn(MultiFactorAuthenticatable $identity, string $guard): void
    {
        $this->store()->begin($identity, $this->applicationFor($guard), Str::lower((string) Str::ulid()));
    }

    /**
     * Forget the identity's sign-in on the application the guard signed it out
     * of, and every proof of it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $guard
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function endSignIn(MultiFactorAuthenticatable $identity, string $guard): void
    {
        $this->store()->forget($identity, $this->applicationFor($guard));
    }

    /**
     * The verification generation a proof the identity is about to make would
     * be stamped with, read before the proof is checked so a generation
     * advanced while it is checked leaves the proof behind; `null` when the
     * identity has no sign-in on the current application the store knows of, so
     * nothing would be recorded.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return ?int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function generationFor(MultiFactorAuthenticatable $identity): ?int
    {
        if ($this->store()->currentSession($identity, $this->application()) === null) {
            return null;
        }

        return VerificationGeneration::current($identity);
    }

    /**
     * Record a proof the identity has just made on the current application,
     * bound to its current sign-in and stamped with the verification generation
     * read before the proof was checked, observing nothing beyond the proof
     * itself, and return it; `null` when the identity has no sign-in the store
     * knows of, so nothing is recorded. The proof, bound as it is now, is
     * stored once the storage connection's open transaction, if any, commits,
     * and never when it rolls back, so a verification undone with it leaves no
     * proof. A store that refuses it throws `ProofRefusedException` then: at
     * once with no transaction open, otherwise from the commit.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  int  $generation
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  ?string  $reference
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function record(MultiFactorAuthenticatable $identity, int $generation, ProofKind $kind, string $method, ?Channel $channel, ?string $reference, Purpose $purpose): ?Proof
    {
        $store       = $this->store();
        $application = $this->application();
        $session     = $store->currentSession($identity, $application);

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
            new ProofBinding($owner->type, $owner->key, $application, $session, $purpose),
            $generation,
        );

        AfterStorageCommit::run($this->container, static fn () => $store->record($proof));

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
        return $this->applicationFor(Auth::getDefaultDriver());
    }

    /**
     * The application a guard acts for on the current request: the one a bound
     * `ApplicationResolver` names for the request, or the guard's name.
     *
     * @param  string  $guard
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function applicationFor(string $guard): string
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        if ($request instanceof Request && $this->container->bound(ApplicationResolver::class)) {
            return $this->container->make(ApplicationResolver::class)->resolve($request);
        }

        return $guard;
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
